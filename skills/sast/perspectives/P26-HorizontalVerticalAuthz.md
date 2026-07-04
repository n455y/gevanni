---
id: P26
name: HorizontalVerticalAuthz
area: V8 Authorization
refs: ASVS V4.1.x, V4.2.x, V4.3.x / WSTG-ATHZ-01, WSTG-ATHZ-02, WSTG-ATHZ-03, WSTG-ATHZ-04 / CS: Authorization, Injection Prevention
---

# P26 — Horizontal & Vertical Authorization

## Overview
Broken access control is consistently the #1 risk in the OWASP Top 10, and within it two failure classes dominate. **Horizontal** (IDOR / BOLA) failures let one user reach another user's resources of the *same* privilege tier — replacing an `/orders/1001` ID with `/orders/1002` returns someone else's order. **Vertical** failures let a lower-privilege subject reach a higher-privilege function or data — a plain `user` calling `/admin/users/delete`, or a `support` role escalating to `admin`. The shared root cause is trusting the request (a path ID, a query param, a hidden form field, a role string in a JWT) instead of re-asserting, server-side, *who* the authenticated principal is and *what* it is allowed to do on *this specific object*. AuthN (knowing who you are) does not imply AuthZ (knowing what you may touch); a missing `WHERE owner_id = ?` clause or a missing role check is all it takes.

## What to check
- Does every object-touching handler bind the resource to the authenticated principal? Look for `findById`, `get(id)`, `SELECT * FROM t WHERE id = ?` with no `AND owner_id = ?` / tenant scoping.
- Can a low-privilege subject reach admin/privileged routes? Enumerate the route table and the middleware chain — is there a global admin guard, or only per-route checks (which are easy to forget on new endpoints)?
- Are object IDs (DB PKs, UUIDs, sequential integers) taken from the request and used as the only key? Try ID increments, UUID leakage in lists, and replaced path/body params.
- Does the app trust client-supplied privilege data — `role`/`isAdmin`/`tenantId` in a JWT, a cookie, a query string, or a hidden form field — that the client can tamper with?
- Are mass-assignment / over-posting paths present where a `role` or `is_admin` field is bound directly from request body to model (Laravel/Eloquent, Rails `update(params)`, Mongoose, Spring `@ModelAttribute`)?
- Is there a forced-browsing path to non-linked functionality (admin consoles, debug endpoints, internal APIs) reachable by guessing URLs?
- Does privilege change (e.g. user→admin via a promotion flow) require re-authentication / step-up auth and emit an audit event?
- Are multi-tenant boundaries enforced per-query, or only once at login? A user who can pass `?tenant=other` and read data has crossed a tenant boundary.

## Static signals
Missing owner/tenant scoping (horizontal leak):
- Node/Mongoose: `Order.findById(req.params.id)` with no `.where('userId', req.user.id)`
- Node/Prisma: `prisma.order.findUnique({ where: { id } })` — no `userId` compound key
- Python/SQLAlchemy: `session.query(Order).filter_by(id=oid).first()` — no `user_id==current_user.id`
- Python/Django ORM: `Order.objects.get(id=oid)` vs safe `Order.objects.get(id=oid, user=request.user)`
- Java/JPA: `em.find(Order.class, id)` without a `where` on owner
- PHP/Laravel: `Order::find($id)` without `->where('user_id', auth()->id())`
- Ruby/Rails: `Order.find(params[:id])` vs `current_user.orders.find(params[:id])`
- Go/gorm: `db.First(&order, id)` without `.Where("user_id = ?", userID)`

Vertical (missing/insufficient role checks):
- Route handler with no middleware/guard: `app.delete('/admin/users/:id', ...)` in Express with no `requireRole('admin')`
- Inline role check that is incomplete: `if (user.role === 'user') return 403;` — forgets `moderator`, `guest`, custom roles, or future roles
- Flask: `@app.route('/admin')` with no `@login_required(role='admin')` / no `@roles_required`
- Spring: controller method missing `@PreAuthorize("hasRole('ADMIN')")` / `@Secured`
- Django: view missing `@user_passes_test(lambda u: u.is_staff)` or `PermissionRequiredMixin`
- Rails: controller lacking `before_action :require_admin`
- Authorization disabled on a base class: `skip_authorization`, Pundit `verify_policy_scoped` skipped, `authorize_resource` removed

Client-trusted privilege / mass assignment:
- JWT payload field read for authz: `if (jwt.role === 'admin')` — JWT is client-readable/tamperable unless signed and verified server-side
- `req.body.role`, `params[:role]`, `@ModelAttribute User user` with `user.role` settable
- Mongoose/Laravel/Rails mass-assign without allow-list (`fillable`/`attr_accessible`/`select`)

## False positives
- A policy engine (Casbin, OPA/Cedar, AWS IAM-style ABAC, Spring Security ACL, Pundit/CanCanCan with verified policies) is applied **consistently** on every object and action, and the policy unit tests cover cross-tenant cases — then per-route checks may be redundant, not missing.
- The object ID is a capability token / signed URL (unguessable, scoped, revocable) rather than a guessable PK — relying on it is intentional.
- The endpoint is intentionally public (public profile, shared link, unauthenticated landing page) — confirm there is genuinely no sensitive data behind it.
- The role check lives in framework middleware applied globally (e.g. a `before_action` in `ApplicationController`, a Nest guard registered app-wide) rather than per-handler — verify it actually covers the target route.
- Tenant scoping is enforced centrally (e.g. a Postgres RLS policy, a Prisma extension, a global query scope) and cannot be bypassed by a raw query — confirm no `manager`/raw-SQL escape hatch exists.

## Attack scenario
1. Attacker authenticates as a normal user `victim_a` and notes their own order URL: `GET /api/orders/5123`.
2. They increment the ID: `GET /api/orders/5124` returns another user's order — **horizontal** IDOR confirmed (no `owner_id` filter).
3. They enumerate IDs with a script (or read a leaked UUID list) and mass-harvest other tenants' orders, invoices, PII.
4. Separately they probe vertical paths: `DELETE /api/admin/users/5123`. The handler lacks a role guard; their session cookie is accepted and the deletion succeeds — **vertical** privilege escalation.
5. Combined: the attacker reads/modifies any user's data and performs admin actions, achieving full account and tenant compromise while leaving no obvious trace beyond log entries.

## Impact
- **Confidentiality**: read access to arbitrary other users' data, other tenants' data, and admin-only data (PII, financial records, secrets).
- **Integrity**: modify or delete other users' records, perform admin actions (user deletion, role grants, config changes), corrupt audit logs.
- **Availability**: delete or lock resources at scale, disable accounts, trigger irreversible admin operations.
- Severity is typically **High to Critical**: a single missing owner filter can expose every record in a table; vertical escalation to admin is effectively full system compromise. Impact scales with data sensitivity and the volume of reachable objects.

## Remediation
Enforce authorization on the object, not just the route; bind every query to the authenticated principal:
```ts
// VULNERABLE — role check only, no horizontal isolation
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).end();
  const order = await Order.findById(req.params.id);     // returns ANY user's order
  return res.json(order);
});

// SAFE — vertical (role) + horizontal (owner) enforced together
app.get('/api/orders/:id', requireAuth, authorize('order:read'), async (req, res) => {
  const filter = req.user.role === 'admin'
    ? { _id: req.params.id }                              // admins scoped by app policy
    : { _id: req.params.id, userId: req.user.id };        // users scoped to own
  const order = await Order.findOne(filter);
  if (!order) return res.status(404).end();               // 404, not 403, to avoid enumeration
  return res.json(order);
});
```
Defense-in-depth: centralize authorization in a policy layer (server-side checks, Pundit/Casbin/OPA, Postgres RLS) so no single forgotten check exposes data; deny by default; use unguessable identifiers only as a complement (never the sole control); audit every privileged action and require step-up re-authentication for role changes.

## References
- ASVS V4.1.x, V4.2.x, V4.3.x
- WSTG-ATHZ-01, WSTG-ATHZ-02, WSTG-ATHZ-03, WSTG-ATHZ-04
- CS: Authorization, Injection Prevention
