---
id: P30
name: FunctionLevelAuthz
area: V8 Authorization
refs: ASVS V4.1.x, V4.2.x, V4.3.x / WSTG-ATHZ-01, WSTG-ATHZ-02, WSTG-ATHZ-04, WSTG-ATHZ-05 / CS: Authorization, Denial of Service, Transaction Authorization
---

# P30 — FunctionLevelAuthz

## Overview
Function-level (missing) authorization — OWASP API/Web Top-10 "Broken Function Level Authorization" — occurs when a sensitive action or endpoint (refund, delete, export, password reset, admin config) is reachable by an authenticated user who lacks the privilege to perform it. The most common root cause is relying on UI gating alone: the front end hides the button, but the back end never re-checks the caller's role or the ownership of the target resource. A second cause is trusting client-supplied feature flags or role claims without server-side verification. Unlike IDOR (object-level), this is about *which action* a user may invoke at all, regardless of which object.

## What to check
- Does every state-changing or privileged endpoint enforce an authorization check on the server, independent of whether the menu item is visible in the UI?
- Are authorization checks applied at the **handler/controller boundary** (middleware, decorator, guard, interceptor) rather than only inside the service layer — and is there a single deny-by-default policy?
- Are role/permission checks specific to the *action* (`billing:refund`, `users:delete`), not just a coarse `role == 'admin'` comparison that breaks when roles are renamed or split?
- Are feature flags (`featureFlags`, `beta`, `enableX`) read from a trusted server config, not from `req.body`/`req.query`/JWT claims that the client can tamper with?
- Does the code trust a client-supplied role (`req.body.role`, `?isAdmin=true`, a JWT `role` field signed with a weak/absent verification) to grant access?
- Is there a central mechanism (route metadata, attribute, annotation) listing required permissions per route, and can you confirm it is actually enforced by a global interceptor? An annotation alone does nothing without the interceptor that reads it.
- Are admin/privileged routes mounted under a path prefix that lacks a blanket guard (e.g., `/admin/*` with no mounted middleware)?
- For tenant/multi-org apps, is the action authorized against the *target* tenant, not just "is the user an admin somewhere"?

## Static signals
No guard on a privileged route:
- Express/Connect: `app.post('/admin/billing/refund', handler)` with no middleware, or a guard only on some sibling routes.
- Next.js: `export async function POST(req){ ... }` in an `/app/admin/**/route.ts` with no session/role check.
- Python Flask/Django: `@app.route('/admin/users/delete', methods=['POST'])` / `path('admin/users/delete', views.delete)` with no `@login_required`/`@permission_required`.
- Django: missing `permission_required` / DRF missing `permission_classes` on a `Viewset` action.
- Spring: `@PostMapping("/admin/refund") public void refund(...)` with no `@PreAuthorize("hasAuthority('billing:refund')")` and no `SecurityFilterChain` rule.
- Rails: `post '/admin/refund', to: 'admin#refund'` with no `before_action :authorize_admin`.
- Laravel: `Route::post('/admin/refund', [AdminController::class, 'refund'])` with no `middleware('can:billing.refund')`.
- Go (net/http, Gin, Echo): `r.POST("/admin/refund", refundHandler)` with no auth middleware on the group.

Trusting client-supplied identity/role/flags:
- `if (req.body.role === 'admin')` / `if (req.query.isAdmin) ...`
- `const role = req.user?.role;` where `req.user` came from an unverified or weakly-verified token.
- `if (req.body.featureFlags?.enableBeta) ...` granting access to gated functionality.
- `@RequestParam String role` / `String role = request.getParameter("role")` used for a decision.
- Spring `@RequestParam`/model attribute binding that lets `user.role`/`user.enabled` be overwritten (mass assignment feeding an authz bypass).

Coarse / brittle checks:
- `if (user.role === 'admin')` instead of `if (user.can('billing:refund'))`.
- Checks scattered in handler bodies with no deny-by-default (missing `else` → fall-through to allowed).

## False positives
- A global guard/interceptor enforces permissions for the whole route group (e.g., Spring Security `SecurityFilterChain`, Rails `before_action` on the controller, Laravel `Gate`/`Policy` via middleware, Django `permission_required`, DRF `DEFAULT_PERMISSION_CLASSES`). Confirm the rule actually covers the specific route.
- The endpoint is intentionally public (`/login`, `/signup`, `/health`, password-reset *request*) — but password-reset *consumption*, email change, etc. must still be authorized.
- Authorization is enforced in middleware but is hard to see because it lives in a separate config file (route map, annotations + global interceptor). Trace the interceptor before calling it a finding.
- A beta feature is temporarily open to all authenticated users by deliberate product decision — still verify it is not also leaking admin-only data.

## Attack scenario
1. Attacker signs up as a low-privileged customer and browses the app; the "Refund" button is hidden in the UI because `user.role !== 'admin'`.
2. Attacker inspects the SPA bundle / network traffic and finds the endpoint `POST /api/v1/billing/refund` that the admin UI calls.
3. Attacker replays the request directly with their own valid session cookie/JWT: `curl -X POST $URL/api/v1/billing/refund -H "Cookie: sid=..." -d '{"amount":9999,"to":"attacker_acct"}'`.
4. The server runs the handler with no role check (UI was the only gate); the refund succeeds.
5. Alternatively, the attacker tampers with a client-controlled field — sets `req.body.role = "admin"` or flips `featureFlags.enableAdminConsole` — and the server trusts it, escalating privileges.

## Impact
- **Confidentiality**: access to admin-only data, exports, other users' records.
- **Integrity**: fraudulent transactions, account deletion, privilege changes, data modification.
- **Availability**: mass deletion or config changes that take the service down.
- Severity scales with the exposed action: a refund/withdrawal endpoint is often **Critical** (direct financial loss); read-only admin views may be High/Medium. Combination with IDOR or mass assignment can amplify to full account/system takeover.

## Remediation
Enforce a single, deny-by-default, action-specific authorization check at the route boundary:
```ts
// VULNERABLE — UI-only gating; endpoint reachable by any authenticated user
app.post('/admin/billing/refund', (req, res) => issueRefund(req.body));

// SAFE — action-specific permission via middleware, deny-by-default
app.post(
  '/admin/billing/refund',
  authn,                          // verify session/JWT
  requirePermission('billing:refund'), // server-side, action-scoped
  (req, res) => issueRefund(req.body),
);
```
```python
# Django/DRF — permission declared per view, enforced by the framework
class RefundView(APIView):
    permission_classes = [IsAuthenticated, HasPermission('billing:refund')]
```
```java
// Spring — method-level, enforced by the security interceptor
@PostMapping("/admin/refund")
@PreAuthorize("hasAuthority('billing:refund')")
public void refund(@RequestBody RefundDto dto) { ... }
```
Never trust client-supplied roles or feature flags for access decisions; read identity/permissions only from a verified session or a signature-checked token, and prefer programmatic ABAC/RBAC (`can(action, resource)`) over string-comparing a role name. As defense-in-depth, add automated tests that assert each privileged route returns `403` for under-privileged roles.

## References
- ASVS V4.1.x, V4.2.x, V4.3.x
- WSTG-ATHZ-01, WSTG-ATHZ-02, WSTG-ATHZ-04, WSTG-ATHZ-05
- CS: Authorization, Denial of Service, Transaction Authorization
