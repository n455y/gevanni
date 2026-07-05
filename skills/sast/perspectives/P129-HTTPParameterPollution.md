---
id: P129
name: HTTPParameterPollution
area: V2 Validation and Business Logic
refs: ASVS V2.x / WSTG-INPV / CS: Query Parameterization, Input Validation
requires: [backend]
---

# P129 — HTTP Parameter Pollution

## Overview
HTTP Parameter Pollution (HPP) occurs when an application or an upstream filter (WAF, middleware) is presented with **multiple values for the same parameter name** and the components disagree on which value wins. The browser, WAF, application framework, and downstream ORM/auth layer each apply different rules — first-wins, last-wins, array-merge, or string-join with a delimiter — so an attacker can submit `?role=user&role=admin` and have the WAF inspect `user` while the application uses `admin`. The root cause is not a single bug but a **mismatch of parameter-resolution semantics across the request pipeline**, exploited whenever validation inspects one representation of the input and the business logic consumes another. HPP is a sibling of injection and mass-assignment: it rarely breaks things on its own, but it becomes the lever that bypasses the filter guarding an injection, auth, or authorization check.

## What to check
- How does each layer resolve a repeated parameter name? Trace the value from edge (WAF/ingress) → web framework → controller → ORM/auth. Flag any layer that takes first/last while a neighbor takes the opposite.
- Does the framework expose multi-value accessors (`req.query.id[]`, `request.args.getlist`, `getParameterValues`, `r.URL.Query()["k"]`, `params[:k]` returning Array) AND a scalar accessor (`req.query.id`)? Confirm the handler uses the right one — scalar accessors silently drop or pick one value.
- Is any security-relevant decision (role/permission assignment, ID allow-list, price, quantity, `is_admin`, `redirect` target, SQL filter) read from a single scalar fetch that an attacker can shadow with a second value?
- Does an ORM or query builder concatenate/`IN`-join a polluted list (`WHERE id IN (...)`, bulk update) where only one value was validated?
- Are mass-assignment / bind-to-model calls (`User.create(req.body)`, Django `ModelForm`, Spring `@ModelAttribute`, Rails `update(params)`) reachable with array- or hash-suffixed keys (`user[role]`, `role[]`) that flip a guarded field into a collection the validator skipped?
- Does a WAF or input-validation rule inspect the **raw** query string / body while the application inspects the **parsed** structure (or vice versa)? ModSecurity `ARGS` vs framework `req.body`, for instance.
- Is the response built by echoing a single value while the action used another (`?callback=legit&callback=<script>`) — HPP as an XSS amplifier?
- Does authentication state derive from a parameter (`?user=`, session token in query) that can be polluted to mismatch identity vs authorization?

## Static signals
Scalar accessor used on a possibly-multi-value input in a security context:
- Node/Express: `req.query.role` (string when single, Array when repeated) flowing into `if (req.query.role === 'admin')` or `User.find({ role: req.query.role })`.
- Python/Flask: `request.args.get('id')` (first) vs `request.args.getlist('id')`; Django `request.GET['id']` (last) vs `.getlist()`.
- Java: `request.getParameter("id")` (first) vs `request.getParameterValues("id")`; Spring `@RequestParam String role` (one value) vs `@RequestParam List<String> role`.
- Go: `r.URL.Query().Get("id")` (first) vs `r.URL.Query()["id"]` (full slice); `r.PostFormValue` vs `r.MultipartForm.Value["id"]`.
- PHP: `$_GET['id']` (last) vs `$_GET['id']` after `parse_str` (last, but arrays via `id[]`); Laravel `Request::input('id')` vs `Request::query('id')`.
- Ruby/Rails: `params[:id]` (last scalar) vs `params[:id]` becoming `Array`/`Hash` when sent as `id[]` / `id[key]`; strong params permitting the wrong shape.
- ASP.NET: `Request["id"]` vs `Request.QueryString.GetValues("id")`; model binder binding a `string` (first) vs `string[]`.

ORM / query construction with polluted input:
- `WHERE id IN (${ids})` built by joining the resolved collection.
- `query("... WHERE role = ?", role)` where `role` arrived as a list and is stringified to `user,admin`.
- Sequelize/Knex/SQLAlchemy `.where({ id })` with `id` an array → `IN` clause over un-validated extra values.

Validation that inspects a different representation than the sink:
- Express middleware `validate(req.query.target)` followed by `redirect(req.query.target)` where pollution swaps the inspected vs used value.
- ModSecurity / custom WAF rule matching against raw `REQUEST_URI` while the app uses the parsed `req.query`.

Mass-assignment with array/hash-suffixed keys reaching a guarded attribute:
- `User.create(req.body)` with `role[]=admin`; Rails `User.new(params[:user])` without `permit`; Spring `@ModelAttribute` binding `roles[0]=ADMIN`.

## False positives
- The framework has a single, consistent resolution rule end-to-end (e.g., a strict router that rejects duplicate keys with HTTP 400) and validation runs on the same representation the sink uses.
- The parameter is validated as a strict scalar type (UUID/integer/enum) before any use, and the framework raises on a non-scalar/Array for that field (rather than coercing or silently dropping).
- The duplicated parameter is genuinely multi-valued and the handler iterates the full list after per-element validation (tag lists, multi-select) — not a single-winner override.
- The endpoint is server-to-server with a trusted single caller and a documented contract forbidding duplicate keys.
- A WAF is absent and the framework's documented behavior (e.g., "last-wins everywhere") matches what the code assumes; there is no inter-layer disagreement to exploit.

## Attack scenario
1. Reconnaissance: the attacker probes a role-assignment endpoint `POST /api/users/update?role=user` and finds the app uses Express (`req.query.role`, **first-wins**) behind a ModSecurity WAF that scans `ARGS` (**last value**).
2. The attacker submits `?role=admin&role=user`. The WAF inspects the last value (`user`), sees nothing malicious, and allows the request.
3. Express resolves `role` to the first value (`admin`) and the handler runs `if (req.query.role === 'admin') grantAdmin(...)`.
4. Result: privilege escalation — the WAF validated `user`, the application acted on `admin`. The same shape bypasses SQL-filter validation (`?id=1&id=1 OR 1=1`), redirects (`?next=/home&next=//evil`), and mass-assignment (`user[role]` shadowing a permitted field).

## Impact
- **Confidentiality**: auth/authorization bypass exposing other users' data; filter bypass enabling SQLi/SSRF enumeration.
- **Integrity**: privilege escalation, mass-assignment of protected fields, fraudulent state changes via a polluted quantity/price/role.
- **Availability**: polluted lists fed to bulk operations or unbounded `IN` clauses can cause resource exhaustion.
- Severity scales with what the bypassed filter guarded: bypassing a WAF in front of a known-vulnerable endpoint can be Critical; mere echo-pollution (XSS amplifier) is typically Medium. Determined by the downstream sink, not HPP itself.

## Remediation
Resolve parameters in exactly one place and validate the resolved value; never let the edge and the app disagree:
```ts
// VULNERABLE — scalar picks one value; WAF may inspect the other
app.get('/redirect', (req, res) => {
  if (!isSafeUrl(req.query.next)) return res.status(400).end(); // inspects first/last only
  res.redirect(req.query.next);
});

// SAFE — collapse to a single validated value, reject ambiguity
app.get('/redirect', (req, res) => {
  const next = [].concat(req.query.next ?? []);
  if (next.length !== 1) return res.status(400).send('unexpected parameter shape');
  if (!isSafeUrl(next[0])) return res.status(400).send('blocked redirect');
  res.redirect(next[0]);
});
```
Defense-in-depth: at the ingress layer (nginx `proxy_pass`, API gateway) reject or canonicalize duplicate query keys so a request never carries two values for one name; ensure WAF rules and the application read the **same** parsed representation of the input.

## References
- OWASP ASVS V2.x — Authentication, session, and access-control / business-logic verification (parameter integrity, input validation)
- OWASP WSTG-INPV — Testing for Input Validation (HTTP Parameter Pollution)
- OWASP Cheat Sheets: Query Parameterization, Input Validation
