---
id: P27
name: ForcedBrowsing
refs: ASVS V4.1.x, V4.2.x / WSTG-ATHZ-04 / CS: Authorization, Insecure Direct Object Reference Prevention
requires: [backend]
---

# P27 — Forced Browsing

## Overview
Forced browsing is an access-control failure where a user reaches an endpoint or resource they were never *offered* (no UI link, no menu entry, a route intended for another role) by guessing or enumerating URLs, path traversal, or directly invoking internal APIs. The defining error is treating "not linked in the UI" as if it were a security control — a posture known as **security through obscurity**. The root cause is always the same: a handler executes its logic without first verifying that *this* authenticated principal is *authorized* for *this* target (function-level authorization), or that the request is coming through the expected entrypoint. Hidden fields (`type=hidden`), unpredictable GUIDs, and "undocumented" routes are not authorization checks; any client can replay or guess the path.

## What to check
- For every route — especially admin, internal, debug, export, batch, or `_internal`/`/api/` prefixed — is there a server-side authorization guard (`requireRole`, `@PreAuthorize`, policy check) that runs *before* the handler logic, regardless of whether the UI exposes the link?
- Are resources addressed by predictable identifiers (sequential integer `id`, `order=1`, `/invoices/42`)? If so, is there an ownership or role check (`resource.owner_id == req.user.id`) on every read and write — i.e., is IDOR/MACL controlled (see P28)?
- Does the app rely on `type=hidden` inputs, undocumented query params (`?admin=1`, `?debug=1`, `?bypass=true`), or request `Referer`/`Origin` headers as the sole gate?
- Are there routes intended "only for internal services" reachable from the public ingress (no network ACL, no service-to-service auth, no mTLS)?
- Does the framework's default routing expose directory listing, static file serving, or `.bak`/`.git`/config files under the web root?
- Are GUID/UUID tokens used as the *only* protection for a resource, under the assumption "unguessable = secure"? (Hard-to-guess ≠ authorized — leaked or enumerated GUIDs fail open.)
- Does the app ship separate admin/management interfaces on default paths (`/admin`, `/console`, `/actuator`, `/phpmyadmin`, `/manager`) without their own auth?
- After authentication changes (login, role change, privilege escalation/demotion), are session-bound permissions re-evaluated, or can a former-admin keep using cached admin routes?

## Static signals
Routes / handlers lacking an authorization decorator or middleware:
- Node/Express: `app.get('/api/admin/export', (req,res) => ...)` — no `requireRole`/`checkPermission` middleware before the handler
- Python/Django: a `view` not wrapped in `@login_required` / `@permission_required`, or a DRF view missing `permission_classes` (or `AllowAny`)
- Python/Flask: `@app.route('/admin/users')` with no `@login_required` and no role check inside
- Java/Spring: `@GetMapping("/api/admin/users")` with no `@PreAuthorize("hasRole('ADMIN')")` / `@Secured` on the method or class
- Go: `mux.HandleFunc("/api/admin/reindex", reindex)` with no auth wrapper
- Ruby/Rails: a controller action with no `before_action :authorize_admin` / Pundit `authorize` call
- PHP/Laravel: a controller method with no `__construct()` `$this->middleware('auth')` / policy, or route outside the `auth` middleware group
- ASP.NET: `[HttpGet]` action missing `[Authorize(Roles="Admin")]` / `[Authorize(Policy=...)]`

Obscurity-as-control / enumeration smells:
- `type="hidden"` inputs carrying decision values: `<input type="hidden" name="role" value="user">`, `<input type="hidden" name="price" ...>`
- Branching on a request flag: `if (req.query.admin === '1') ...`, `if (req.headers['x-internal']) ...`
- Sequential IDs in path/route params used without ownership check: `GET /api/orders/:id`, `DELETE /invoices/:id`
- Static-file / directory serving mapped to web root: `app.use(express.static('.'))`, Django `STATIC_ROOT` mis-scope, Spring `static`/`resources`, `app.UseStaticFiles(new PhysicalFileReader(...))`
- Backstage endpoints: paths containing `admin`, `internal`, `debug`, `dev`, `test`, `backup`, `console`, `actuator`, `__debug__`, `_profiler`

## False positives
- The route *does* have an explicit, tested authorization guard (decorator, middleware, policy) verified to reject unauthorized principals — confirm by reading the guard, not just its presence in a shared base class.
- The endpoint is genuinely network-isolated (private subnet + mTLS / service mesh auth) and not reachable from public ingress — then forced browsing from an external user is not reachable (still rate Medium if lateral movement is possible).
- A GUID/UUID is used *in addition to* a real authorization check (e.g., for enumeration deterrence) — defense-in-depth, not a flaw.
- The resource is intentionally public (login page, public marketing API, health check with no sensitive data).
- The "hidden" field is informational only and the server re-derives the value (e.g., server reads `role` from the session, not the submitted field).

## Attack scenario
1. Attacker, a low-privilege user, opens browser devtools or a proxy and notices `/api/admin/export` is never surfaced in the UI but is referenced in a JS bundle or guessed from route naming conventions.
2. They request `GET /api/admin/export` directly with their own session cookie.
3. The server has no function-level authorization check on that route (only the UI hid the link); the handler executes and returns the full user database export.
4. Separately, they enumerate sequential IDs: `GET /api/invoices/1`, `/2`, `/3` ... harvesting other tenants' invoices because ownership is never validated.
5. They pivot to account takeover, data exfiltration, or fraud using the harvested admin/tenant data.

## Impact
- **Confidentiality**: full disclosure of other users' data, admin functions, internal config, PII — the hallmark of forced browsing.
- **Integrity**: unauthorized writes — admin actions (delete, role grants), record tampering, settings changes.
- **Availability**: admin endpoints may allow resets, reindexes, mass deletes, or shutdown.
- Severity scales steeply with the exposed surface: a hidden *read-only* debug route is Medium; an unlinked admin export or management console is High/Critical; full IDOR across tenants is Critical.

## Remediation
Authorize on the server, on every route, by reference — never by obscurity:
```ts
// VULNERABLE — "hidden" route, no authorization
app.get('/api/admin/export', (req, res) => exportAll());
// also vulnerable: IDOR with no ownership check
app.get('/api/invoices/:id', (req, res) =>
  res.json(Invoice.findById(req.params.id)));

// SAFE — function-level + object-level authorization
app.get('/api/admin/export',
  requireRole('admin'),                       // function-level
  (req, res) => exportAll());
app.get('/api/invoices/:id', authn, async (req, res) => {
  const inv = await Invoice.findById(req.params.id);
  if (!inv || inv.ownerId !== req.user.id) return res.sendStatus(404); // object-level, opaque 404
  res.json(inv);
});
```
Deny by default: apply a global authorization middleware that rejects unless a route explicitly opts in. Use opaque 404s (not 403) when a resource should not even be *visible* to the caller. Prefer random/unguessable IDs only as a complement to, never a substitute for, server-side authorization. Defense-in-depth: network-segregate admin surfaces, require step-up re-authentication, and monitor for unexpected route access.

## References
- OWASP ASVS V4.1.x (general access control), V4.2.x (operation-level / IDOR) — Verify that the application enforces authorization on every trusted route and per object.
- OWASP WSTG-ATHZ-04 — Testing for Bypassing Authorization Schema (forced browsing / IDOR).
- OWASP Cheat Sheets: Authorization; Insecure Direct Object Reference Prevention; REST Security.
