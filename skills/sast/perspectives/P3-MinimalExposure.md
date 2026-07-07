---
id: P3
name: MinimalExposure
refs: ASVS V1.2.x, V1.14.x / WSTG-CONF-05 / CS: Architecture Cheat Sheet
---

# P3 — MinimalExposure

## Preconditions

The code exposes endpoints or interfaces.


## Overview
Minimal exposure is an architectural principle: every route, port, and surface that an application exposes beyond its intended trust boundary increases the attack surface. Admin consoles, debug toolbars, health/metrics endpoints, internal/management APIs, and gRPC/admin ports are routinely mounted on the same listener as public traffic — or registered unconditionally regardless of environment — and then forgotten. The root cause is not a single missing check but a configuration drift: scaffolding and development aids ship to production, the default listen address is `0.0.0.0`, and "temporary" diagnostic routes are never gated behind authentication, authorization, or network segmentation. The result is a large footprint of low-effort, high-impact findings (unauthenticated admin panels, open `/actuator`, exposed Swagger/GraphQL introspection) that violate least privilege and least exposure at the architecture layer.

## What to check
- Is every administrative, diagnostic, or internal endpoint authenticated *and* authorized (role-gated), not merely present-but-undocumented?
- Are debug routers, profiler endpoints, and dev-only middleware (`app.use('/debug', ...)`, `express-debug`, `werkzeug` debugger, Django `DEBUG=True`, Spring Boot DevTools) disabled or unmounted in production?
- Are framework "all routes" introspection surfaces exposed to untrusted callers — Spring Boot `/actuator`, Django `/admin` if `is_staff` gates are weak, FastAPI/Swagger `/docs` + `/openapi.json`, GraphQL introspection, Flask `/apidoc`?
- Is the application listening on `0.0.0.0` (or `::`) when it should bind to a loopback/private interface behind a reverse proxy?
- Are management/data-plane ports separated? gRPC, JMX, metrics (Prometheus `/metrics`), and admin ports should not share the public listener.
- Are environment-conditional guards actually evaluated (no dead code, env var actually set in prod), and do they default-deny when the variable is absent?
- Are health checks (`/healthz`, `/health`) leaking version/host/dependency details instead of a bare 200?
- Are background/scheduled jobs, queue workers, or seed scripts mounted as reachable HTTP routes by mistake?

## Static signals
Unconditional mount of admin/internal routers (Node/Express):
- `app.use('/admin', adminRouter)`
- `router.use('/internal', internalRoutes)`
- `app.use('/debug', require('./debug'))`
- `app.use('/metrics', promMetrics)` with no auth middleware

Environment guards that are inverted, missing, or default-permit:
- `if (process.env.NODE_ENV !== 'production') app.use('/admin', ...)` — admin only added in non-prod (good); but `if (NODE_ENV !== 'production')` inverted to `=== 'production'` is a bug
- `app.use('/admin', adminAuth, adminRouter)` only — verify `adminAuth` is not a no-op
- `if (DEBUG) ...` where `DEBUG` defaults to truthy

Python (Flask/Django/FastAPI):
- `app.run(host='0.0.0.0', debug=True)` — debug + public bind
- `DEBUG = True` in settings shipped to prod
- `@app.route('/admin/...')` without `@login_required` / `@permission_required`
- FastAPI `app = FastAPI()` with `/docs` not disabled (`docs_url=None, openapi_url=None`)

Java/Spring Boot:
- `management.endpoints.web.exposure.include=*` (application.yml)
- `@RestController @RequestMapping("/actuator/...")` custom endpoints with no security
- `server.address=0.0.0.0`; actuator on same port as app (`management.server.port` unset)

Go:
- `http.ListenAndServe(":8080", ...)` with admin handlers in the same mux
- `expvar`/`pprof` registered on the public mux: `import _ "net/http/pprof"`

Ruby/Rails:
- `routes.rb` mounting `rails_admin` or `sidekiq/web` without `constraints` / basic auth
- `config.consider_all_requests_local = true` in prod

PHP:
- `/wp-admin`, `/phpmyadmin`, `/adminer.php`, `.env`, `/.git/config` reachable from web (webroot leak)

Generic network/bind signals:
- `bind 0.0.0.0`, `listen 8080`, `EXPOSE 8080` without a proxy in front
- Docker `ports:` (host-published) vs `expose:` (container-only)

## False positives
- The endpoint is explicitly behind an IP allow-list, VPN, mTLS, or service mesh authorization policy (verify the control is actually enforced at the boundary, not just documented).
- `/admin` is restricted by infrastructure-level network segmentation (private subnet, no internet path) AND by application auth — defense in depth, lower severity.
- Health endpoint returns only a static `200 OK` with no body (no info leak); acceptable to expose.
- Debug toolbar is gated by a strict per-request token AND restricted to internal IPs.
- The `0.0.0.0` bind is intentional because the app is a sidecar/proxy in a pod where only the mesh egress is reachable — confirm via deployment topology.

## Attack scenario
1. Reconnaissance: attacker runs `ffuf`/`dirb` against `https://app.example.com` and discovers `/actuator/env` (Spring Boot) or `/debug` (Express).
2. `/actuator/env` returns live environment variables including `SPRING_DATASOURCE_PASSWORD` and API keys, unauthenticated.
3. Separately, `/actuator/jolokia` or `/debug.heapdump` exposes heap data containing session tokens and credentials in memory.
4. Attacker pivots: uses the leaked DB password to connect to the database (if reachable) or forges a session using exfiltrated tokens — full compromise without any memory-corruption or injection exploit.

## Impact
- **Confidentiality**: direct leakage of secrets, env vars, heap data, source maps, and internal topology.
- **Integrity**: unauthenticated admin routes allow data modification, user/role tampering, or config changes.
- **Availability**: debug/shutdown endpoints (e.g., `/actuator/shutdown`, `/debug/reset`) enable denial of service.
- Severity scales with what the surface exposes: a bare `/health` is informational; an open `/actuator/*` or admin console with weak auth is Critical.

## Remediation
Gate internal surfaces by environment, auth, and network; default-deny:
```ts
// VULNERABLE — mounted unconditionally, no auth
app.use('/admin', adminRouter);
app.use('/debug', debugRouter);

// SAFE — admin only in non-prod AND behind auth; debug never mounted in prod
if (process.env.NODE_ENV !== 'production') {
  app.use('/admin', requireAuth, requireRole('admin'), adminRouter);
}
// never mount debugRouter in production builds
```
Defense-in-depth: bind management endpoints to a loopback interface or a separate port reachable only inside the VPC, disable framework introspection (`docs_url=None`, actuator `include=health` only, GraphQL introspection off), and enforce least exposure at the load balancer/WAF layer so that even an accidental mount is not internet-reachable.

## References
- OWASP ASVS V1.2.x (architecture / trust boundaries), V1.14.x (admin/diagnostic interface controls)
- OWASP WSTG-CONF-05 — Review Old Backup and Unreferenced Files for Sensitive Information / exposed admin interfaces
- OWASP Cheat Sheet: Architecture, REST Security, Infrastructure as Code
