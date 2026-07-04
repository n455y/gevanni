---
id: P100
name: LegacyEndpoint
area: V4 API and Web Service
refs: ASVS V13.x / WSTG-CONF-05, WSTG-ATHZ-01 / CS: REST Security, OWASP API9:2023 Improper Inventory of Assets
---

# P100 — LegacyEndpoint

## Overview
A legacy endpoint is an older, deprecated, beta, internal, or previously-versioned API surface (`/v1`, `/legacy`, `/beta`, `/internal`) that still runs in production but is no longer covered by the current security controls. The root cause is almost always **inventory drift**: when a new major version or hardened rewrite ships, the old routes are left mounted "for backward compatibility" without inheriting the new authentication, authorization, input-validation, rate-limiting, or logging middleware. Attackers actively probe for these undocumented or un-monitored paths because they are the path of least resistance — a fortified `/v2` front door is meaningless if `/v1` still accepts unauthenticated requests against the same data store.

## What to check
- Are older API versions (`/v1`, `/v0`, `/api/old`), deprecated routes, `beta`, `alpha`, `internal`, `admin-legacy`, `mobile-legacy`, or partner-specific endpoints still mounted in the router?
- Does the legacy route inherit the **same** authentication, authorization (RBAC/ABAC + object-level ownership checks), input validation/schema, rate-limiting, CORS, and audit-logging middleware as the current version — or does it bypass any of them?
- Is the legacy path explicitly excluded from coverage in a recent authz refactor (e.g., a guard list, an `unless` clause, a `skip` set, an allow-list of "no-auth" routes)?
- Are the legacy endpoints documented in the API inventory / OpenAPI spec, or do they exist only in code (undocumented = unmonitored)?
- Does the deprecation actually have a sunset date, `Deprecation`/`Sunset` HTTP headers, and access restrictions — or is it open-ended and indefinitely reachable?
- Does the legacy handler still call current data-access code, ORM models, or stored procedures whose authorization was tightened for `/v2` but the fix never applied to `/v1`?
- Is the legacy route reachable from the public internet, or only via an internal network segment that is itself internet-exposed (load balancer, API gateway wildcard)?
- Do beta/internal endpoints accept production credentials and operate on production data?

## Static signals
Route mounting of legacy/old versions alongside a newer one:
- Node/Express: `app.use('/v1', v1Router)` next to `app.use('/v2', auth, v2Router)`; `app.use('/legacy/*', legacy)`; `router.use('/beta', betaRouter)`
- Python (Flask/FastAPI/Django): `@app.route('/v1/users')`, `@app.include_router(v1_router, prefix='/v1')`, `urlpatterns = [path('v1/', old_views)]`
- Java/Spring: `@RequestMapping('/v1/**')`, `@RestController` classes under a `/legacy` package, `@RequestMapping(produces='application/vnd.company.v1+json')`
- Go (gin/echo/chi): `r.Group('/v1')`, `e.GET('/v1/health', legacyHealth)`
- PHP (Laravel/Slim): `Route::prefix('v1')->group(...)`, `$app->group('/v1', ...)`
- Ruby (Rails/Sinatra): `namespace :v1 do`, `get '/v1/*'`

Authentication/authorization exclusion patterns:
- `unless: ['v1', 'legacy']`, `skip_before_action :authenticate!, only: [:legacy]` (Rails)
- `auth.except(['/v1'])`, `app.use(auth.unless({ path: ['/v1'] }))` (express-jwt)
- Spring: `permitAll()` matching `/v1/**`, `WebSecurityConfig` `antMatchers('/v1/**').permitAll()`
- FastAPI `dependencies=[Depends(get_current_user)]` present on `/v2` routers but absent on `/v1`
- A central guard/middleware whose route list was edited to drop legacy paths during a refactor

Deprecation signals (or absence thereof):
- `deprecate`, `deprecated`, `sunset`, `Deprecation`, `Sunset`, `TODO: remove`, `@Deprecated` near route definitions
- No `Sunset`/`Deprecation` header set on responses; no `410 Gone`/`426 Upgrade Required` migration enforcement
- Beta/internal flags: `isBeta`, `internal`, `x-internal`, `debug`, `test` route prefixes still enabled in production config

## False positives
- The legacy route has identical auth/authz/validation/logging to the current version AND a documented sunset plan with a concrete removal date — this is "managed backward compatibility", severity Medium at most (informational if access is also rate-limited and audited).
- The endpoint is fully decommissioned: returns `410 Gone` for all methods, is not wired to any data access, or is gated behind an IP allow-list / mTLS that excludes public traffic.
- The "legacy" prefix is purely cosmetic branding and the route shares the exact same global middleware chain as everything else (no `unless`/`skip`/`permitAll` exception).
- The route is internal-only and bound to a loopback/private interface with no proxy exposure — verify the network path, do not assume.

## Attack scenario
1. During reconnaissance the attacker discovers the app advertises `/api/v2/...` and guesses or fuzzes `/api/v1/...`, `/v1`, `/legacy`, `/beta`, `/old`, `/internal` using a wordlist (ffuf, dirb, route-detection based on the framework's 404-vs-401 behavior).
2. `/v1/users/:id` responds `200` without an `Authorization` header — the current `/v2/users/:id` requires a bearer token and enforces object-level authz. The `/v1` handler was never updated when `/v2` added ownership checks.
3. The attacker iterates `:id` (IDOR) or simply reads every record, because `/v1` has neither authentication nor rate-limiting.
4. Because the legacy path is excluded from logging/alerting (no `auth` middleware → no audit hook), the mass exfiltration goes unnoticed.
5. If `/v1` also lacks input validation, the attacker pivots to SQL injection / parameter pollution on the old handler, which still calls the production database.

## Impact
- **Confidentiality**: unauthenticated or weakly-authenticated read/write of production data — full account exposure, PII leakage, IDOR-driven mass extraction.
- **Integrity**: legacy endpoints that bypass authz allow unauthorized create/update/delete; if input validation is also absent, injection can corrupt or overwrite records.
- **Availability**: undocumented internal/debug endpoints (`/internal/shutdown`, `/v1/debug`, `/beta/reindex`) can be abused to trigger expensive operations or outages.
- Severity scales with the delta between legacy and current controls: a legacy route with zero auth on production data is Critical; a legacy route with identical controls but no sunset is Low/Medium.

## Remediation
Inherit the current middleware on legacy routes and enforce a real sunset:
```ts
// VULNERABLE — /v1 has no auth, /v2 does
app.use('/v1', v1Router);                 // no auth, no validation, no logging
app.use('/v2', auth, rateLimit, v2Router);

// SAFE — legacy route inherits identical guards + deprecation + sunset
import sunset from './middleware/sunset'; // sets Deprecation & Sunset headers
app.use('/v1', auth, rateLimit, auditLog, sunset('2026-12-31', '/api/v2'), v1Router);
```
```python
# VULNERABLE — FastAPI v1 router has no dependency
app.include_router(v1_router, prefix='/v1')
app.include_router(v2_router, prefix='/v2', dependencies=[Depends(verify_token)])

# SAFE — apply the same dependency + deprecation status to v1
app.include_router(
    v1_router, prefix='/v1',
    dependencies=[Depends(verify_token), Depends(enforce_sunset('2026-12-31'))],
    deprecated=True,
)
```
Defense-in-depth: maintain a single source-of-truth API inventory (OpenAPI spec generated from code), fail-closed global middleware that explicitly allow-lists routes rather than black-listing legacy ones, and monitor for 401/403-vs-200 anomalies on any path matching `/(v[0-9]|legacy|beta|old|internal)/`. Never ship a new authz fix without grepping for older routes that call the same data-access layer.

## References
- OWASP ASVS V13.x — API and Web Service protection, including versioning and deprecation
- OWASP WSTG-CONF-05 — Review Old, Backup, and Unreferenced Files for Administrative Content
- OWASP WSTG-ATHZ-01 — Testing Directory Traversal/File Inclusion / authorization bypass on legacy paths
- OWASP Cheat Sheet: REST Security
- OWASP API Security Top 10 2023 — API9:2023 Improper Inventory of Assets (and API4:2023 Unrestricted Resource Consumption via legacy rate-limit gaps)
