---
id: P25
name: ServerSideAuthz
area: V8 Authorization
refs: ASVS V4.1.x, V4.2.x, V4.3.x / WSTG-ATHZ-01, WSTG-ATHZ-02, WSTG-ATHZ-03, WSTG-ATHZ-04 / CS: Authorization, Access Control, Insecure Direct Object Reference Prevention
requires: [backend]
---

# P25 — Server-Side Authorization

## Overview
Broken Access Control is consistently the #1 category in OWASP Top 10 because authorization is easy to get wrong and easy to forget. Server-side authorization (authz) means the **server independently verifies, on every request, that the authenticated principal is allowed to perform the requested action on the requested resource** — it never trusts claims carried by the client (request body, JWT fields the user could have minted, hidden form fields, or the simple fact that the UI hid a button). The two failure modes are horizontal (IDOR: user A accesses user B's record by tampering an ID) and vertical (a regular user invokes an admin-only route). The root cause is almost always a missing or inconsistent guard: middleware applied to some routes but not others, a default-deny posture that was inverted to default-allow, or trust in a client-supplied attribute that should have been resolved from the session.

## What to check
- Does **every** sensitive route enforce authorization through a centralized mechanism (middleware, guard, decorator, interceptor), or are checks scattered/ad-hoc into individual handlers (where some will inevitably be missed)?
- Is the principal's identity/role resolved **from the server-side session or verified token**, never from `req.body.role`, a JWT claim that is not re-validated, a query parameter, or a hidden field?
- For object-level access (IDOR): does the handler verify that the resource identified by `req.params.id` / path / query actually **belongs to** (or is visible to) the authenticated user, by querying against the user's tenant/owner id — not merely that the ID exists?
- Are admin/privileged routes guarded by role/permission checks (e.g. `requireRole('admin')`), and is the **deny path the default** (fail-closed) so a missing rule rejects rather than allows?
- Does tenant isolation enforce that data cannot cross tenant boundaries even when IDs are guessed (multi-tenant scoping on every query)?
- Are authorization decisions logged, and do they survive refactors (i.e. enforced via a policy layer like CASL, OPA, Spring Security, rather than inline `if (user.role)` sprinkled in views)?
- Are state-changing operations protected against CSRF **in addition to** authz (a valid session alone is not consent)?
- Are there routes that bypass the global authz middleware intentionally (public, health, login) — and are they confirmed to contain no sensitive logic or data exposure?

## Static signals
Role/identity sourced from the request body, query, or JWT claim without re-validation:
- `if (req.body.role === 'admin')` / `if (body.get('isAdmin'))` / `if (request.args.get('role') == 'admin')`
- `const role = req.headers['x-role']` / `userType = request.headers.get('X-User-Type')`
- Reading a role straight off an unverified JWT payload: `const { role } = jwt.decode(token)` (no signature verify), or trusting `req.user.role` populated from a client-controlled field.

Missing guard on a state-changing route while siblings have one:
- `app.delete('/users/:id', handler)` next to `app.post('/users', authz, handler)` — the delete lacks the middleware.
- Flask: a `@app.route` missing `@login_required` / `@roles_required`; Django: a CBV missing `@method_decorator(login_required)` or a URL omitted from `LOGIN_REQUIRED_MIDDLEWARE`.
- Spring: `@PreAuthorize("hasRole('ADMIN')")` present on some `@RequestMapping` methods but absent on others in the same controller.

Object fetched without ownership scoping (IDOR):
- `User.findById(req.params.id)` / `User.objects.get(id=pk)` / `repo.findById(id)` returned directly — no `.filter(owner=request.user)` / `.filter(tenant=user.tenant)`.
- `db.users.findOne({ _id: req.params.id })` with no `userId`/`tenantId` predicate.
- JPA `userRepository.findById(id)` without a `@Where` tenant clause or a `@PreAuthorize` owner check.

Default-allow logic (inverted allow-list):
- `if (user.role === 'admin') { return allow() } /* else fall through and execute */`
- Bouncer/SpEL/policy that returns `true` when no rule matches.

## False positives
- A centralized guard/interceptor (NestJS `AuthGuard` + `RolesGuard` implementing `canActivate`, Rails `before_action`, Spring Security `SecurityFilterChain`, Django middleware/`@permission_required`) is proven to cover **all** routes in scope, including the one under review — verify by listing routes without a guard rather than trusting convention.
- The route is genuinely public (login, registration, password reset request, health check, marketing pages) and exposes no user-specific or privileged data.
- The ID is an unguessable, server-issued, single-use capability (e.g. signed pre-signed URL, opaque UUID with rate limiting and per-user validity) — though this is weaker than true authz and should be flagged as defense-in-depth only.
- The handler delegates to a service layer that enforces authz uniformly, and the service is the only entry point — confirm no second caller bypasses it.

## Attack scenario
1. The application shows an "Edit Account" form at `GET /account/12345` where `12345` is the user's own id; the UI hides admin controls for non-admins.
2. Attacker (a normal user) notices the route `/api/admin/users/:id/delete` referenced in client JS even though the button is hidden, and that authorization is only enforced by the SPA not rendering the button.
3. Attacker calls `DELETE /api/admin/users/12345` directly with their own session cookie. The route lacks `requireRole('admin')` (it was applied to `/admin/*` page routes but not the API), so the server executes it.
4. In a horizontal variant, attacker changes `GET /api/orders/1001` to `/api/orders/1002` (another customer's order); `Order.findById(id)` returns it because there is no `userId` predicate, leaking PII and enabling fraud.

## Impact
- **Confidentiality**: full read of other users' data, tenant data exfiltration, PII/PHI/PCI leakage, admin-only data exposed to any user.
- **Integrity**: unauthorized modifications or deletions, privilege escalation to admin, fraudulent transactions, account takeover by deleting/modifying victims.
- **Availability**: mass deletion or destructive admin actions performed by a low-privilege account.
- Severity scales steeply: a single unguarded admin route = full compromise; a single unguarded object lookup = one-record breach per request, trivially scriptable to "all records".

## Remediation
Enforce authz centrally and fail-closed; scope object access by owner/tenant:
```ts
// VULNERABLE — role trusted from client; object fetched without ownership check
app.delete('/api/users/:id', (req, res) => {
  if (req.body.role === 'admin') {            // attacker controls req.body
    return User.findByIdAndDelete(req.params.id).then(() => res.send());
  }
  res.status(403).send();
});
app.get('/api/orders/:id', (req, res) => {     // IDOR — no ownership filter
  Order.findById(req.params.id).then(o => res.json(o));
});

// SAFE — server-side role from verified session; object scoped to the caller
app.delete('/api/users/:id',
  requireRole('admin'),                        // centralized guard, fail-closed default
  (req, res) => User.findByIdAndDelete(req.params.id).then(() => res.send()));
app.get('/api/orders/:id', requireLogin, (req, res) => {
  Order.findOne({ _id: req.params.id, userId: req.user.id })  // ownership enforced
    .then(o => o ? res.json(o) : res.status(404).send());     // 404 not 403 to avoid enumeration leak
});
```
One-line defense-in-depth: centralize every decision in a policy engine (CASL/OPA/Spring Security) and write an automated test that, for each route, asserts a forbidden principal gets `403` and that a user cannot read another tenant's object.

## References
- OWASP ASVS V4.1.x (general access control), V4.2.x (operation-level), V4.3.x (field/object-level / IDOR)
- OWASP WSTG-ATHZ-01 (path/bypass), WSTG-ATHZ-02 (bypass authz schema), WSTG-ATHZ-03 (privilege escalation), WSTG-ATHZ-04 (IDOR)
- OWASP Cheat Sheets: Authorization, Access Control, Insecure Direct Object Reference Prevention
