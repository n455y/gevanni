---
id: P28
name: DenyByDefault
area: V8 Authorization
refs: ASVS V4.1.x, V4.3.x / WSTG-ATHZ-02 / CS: Authorization - Enforcement Matrix, Authorization - Testing for Bypass
requires: [backend]
---

# P28 — DenyByDefault

## Overview
"Deny by default" (fail-closed / allow-list authorization) means an access decision resolves to **deny** unless a rule explicitly grants access. The opposite — deny-listing or `default: allow` — lets every uncovered case, every future code path, and every error fall through to a permitted outcome. Most real authorization bypasses (broken function-level access control, forced browsing, IDOR escalation, privilege creep through unhandled roles) are downstream symptoms of a missing default-deny posture. The root cause is an inverted predicate: code asks "is there a reason to block?" instead of "is there a reason to allow?", or it forgets to halt the request on a failed check, so execution continues past the guard.

## What to check
- Does the authorization logic use an **allow-list** (`isExplicitlyAllowed(...` → otherwise deny) rather than a deny-list (`isBlocked(...` → otherwise allow)?
- Does every `switch`/`match`/`case` over role/permission have a `default` branch that **denies** (not `next()`/`return true`/pass-through)?
- After a failed permission check, is control flow **definitely terminated** — `return`, `throw`, or equivalent — before any privileged work runs? Look for guards that set a status but then fall through to the handler body.
- Are exceptions during auth evaluation handled fail-**closed** (treat unknown → deny), or does a thrown error in the policy/DB layer fall open (request proceeds with no decision)?
- Is there a central policy/rail (middleware, decorator, annotation, interceptor) so authorization cannot be silently omitted on a new route, or can a developer add an endpoint with no guard by default?
- Are object/instance-level checks present *in addition to* function-level checks, or does possession of a valid ID (predictable/forced browsing) grant access?
- Does the framework's default for a new route default to **authenticated + authorized**, or to **public**?
- On positive decisions, is the grant minimal (least privilege), or does "logged in" equal "everything"?

## Static signals
Failed-check fall-through (status set, but flow not stopped):
- `if (!ok) res.status(403); /* no return */ res.send(data);` (Express)
- `if (!canAccess) resp.sendError(403); /* no return */ doWork();` (Java)
- `if not ok: set_status(403)  # no raise/return` (Python/FastAPI/Flask)

Deny-list / inverted predicate:
- `if (user.role === 'blocked') deny; else allow;`
- `if (BLOCKED_ROLES.includes(role)) return 403; /* else pass */`
- `unless user.banned? then authorize end`

`default:` branch that permits:
- `switch (role) { case 'admin': allow(); break; default: next(); }`
- `match role { 'admin' => true, _ => true }` (Rust — last arm allows)
- `case "$role" in admin) allow;; *) allow;; esac` (Bash)

Fail-open exception handling:
- `try { ok = policy.check() } catch { ok = true }` / `catch (e) { next() }` / `except: pass`
- `if (policyError) { log(e); } /* proceeds with undefined ok */`

Authz as a positive default that must be opted out of, or omitted entirely:
- Route registered with no auth middleware: `app.post('/admin/import', handler)` (no guard)
- Spring `@PreAuthorize` missing on a new `@RestController` method
- Django view without `@login_required` / DRF view without `permission_classes`
- Gin/Echo handler without an `Auth()` middleware in the chain

Missing object-level (IDOR-friendly) checks:
- `Order.findById(req.params.id)` with no `where: { userId: req.user.id }`
- `repo.findById(id)` then used directly, never comparing ownership

## False positives
- A framework or gateway enforces default-deny at the boundary: Spring Security with `denyAll()` baseline + explicit `hasAuthority`, AWS IAM/OPA policies that default-deny, Kubernetes RBAC, or a service mesh authz policy with `action: DENY` as the catch-all. Verify the catch-all actually covers the unhandled case.
- The route is intentionally public (login, health check, public asset) and public access is the explicit, reviewed decision — not an omission.
- The check is performed in a separate, mandatory interceptor/filter earlier in the pipeline that this handler relies on; confirm the interceptor is non-bypassable and applies to this path.
- A `default` arm that permits is safe only when an earlier guard already denied unknown roles (i.e., the switch is reachable only after authentication narrowed the value to a known set).

## Attack scenario
1. The app authorizes by `switch(role)` over a fixed role list; a future release adds `role: 'auditor'` to the user model but not to the switch. `default: next()` lets auditors through every protected handler.
2. An attacker obtains (or is assigned) the `auditor` role — e.g., via a separate over-grant bug, a stale test account, or a token-forgery that sets `role=auditor`.
3. They hit `/admin/users/delete?id=...`. The switch's `default` branch calls `next()`, so the handler runs with no real authorization.
4. With object-level checks also missing, the attacker iterates `id` (forced browsing / IDOR) and deletes or reads arbitrary users — full broken access control, all because the default was "allow".

## Impact
- **Confidentiality**: unauthorized read of other users' data, admin panels, internal resources.
- **Integrity**: unauthorized create/update/delete, privilege escalation, account takeover via admin functions.
- **Availability**: unauthorized destructive actions (mass delete, config changes, shutdown).
- Severity scales steeply: a default-allow on an unauthenticated route is critical; on an authenticated-but-under-privileged route it is high; the blast radius grows with the privileges any unhandled role carries. One missing `return` on an admin endpoint can be a full compromise.

## Remediation
Structure every access decision as allow-list with fail-closed error handling, and centralize it so it cannot be omitted:
```ts
// VULNERABLE — deny-list, default-allow, fall-through, fail-open
function authz(req, res, next) {
  try {
    if (req.user.role === 'blocked') return res.sendStatus(403);
    next();                       // default: ALLOW for every other role / error
  } catch (e) {
    next();                       // fail-OPEN on policy error
  }
}
app.post('/admin/users/delete', deleteHandler);  // no guard wired at all

// SAFE — explicit allow-list, fail-closed, mandatory rail
function requirePermission(action) {
  return async (req, res, next) => {
    let ok = false;
    try {
      ok = await policy.isExplicitlyAllowed(req.user, action, req.params); // ownership too
    } catch (e) {
      return res.sendStatus(403);              // fail-CLOSED
    }
    if (!ok) return res.sendStatus(403);       // deny by default
    next();
  };
}
app.post('/admin/users/delete', requirePermission('user:delete'), deleteHandler);
```
Defense-in-depth: enforce default-deny at the framework boundary too (Spring Security `denyAll()` baseline, a global authz middleware on every route, or an OPA/IAM policy whose catch-all is `DENY`), and add a CI/test that fails if any route is registered without an authorization guard.

## References
- ASVS V4.1.x, V4.3.x
- WSTG-ATHZ-02
- CS: Authorization - Enforcement Matrix, Authorization - Testing for Bypass
