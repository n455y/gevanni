---
id: P107
name: AdminInterfaceExposure
area: V13 Configuration
refs: ASVS V14.x / WSTG-CONF-05, WSTG-CONF-11 / CS: Administration Cheat Sheet
---

# P107 — AdminInterfaceExposure

## Overview
Administrative and operational interfaces — admin consoles, management APIs, framework diagnostic endpoints (Spring Boot Actuator, Django debug toolbar, ASP.NET diagnostics), database web consoles (H2, phpMyAdmin, Redis Commander), and feature-flag/queue dashboards — are the highest-value targets in any application. When they are reachable from the public network, behind weak or default credentials, or without MFA, an attacker can convert one exposed endpoint into full system compromise: environment/secret disclosure, RCE via shutdown or refresh endpoints, account takeover via direct user management. The root cause is almost always **default-open exposure plus missing network isolation**: frameworks ship management endpoints enabled for developer convenience, and they are never gated down before deployment.

## What to check
- Are admin/management routes (`/admin`, `/manage`, `/console`, `/dashboard`, `/actuator/**`, `/wp-admin`) reachable from the public Internet, or only from an internal/VPN/loopback network?
- Are management endpoints and the public app served on the **same port** (no separation between a public port and an internal management port)?
- Is strong authentication enforced on every management path? MFA? Are default credentials (`admin/admin`, `admin/password`, H2 empty sa password) still in play?
- Is there an IP allow-list / network ACL / security group in front of the admin interface, or is it open to `0.0.0.0/0`?
- Which framework diagnostic endpoints are exposed, and which sensitive ones (`heapdump`, `threaddump`, `env`, `configprops`, `mappings`, `shutdown`, `/health` revealing dependency detail) leak secrets or enable RCE?
- Are database/queue/cache web consoles (H2 `/h2-console`, phpMyAdmin, Redis Commander, RabbitMQ management, Mongo Express) enabled in production?
- Does `/health` or `/metrics` (intended to be public) leak internal topology, dependency versions, env vars, or stack traces?
- Is TLS enforced, and are admin cookies `Secure`/`HttpOnly`/`SameSite`?
- Is the admin interface on a **separate hostname/subdomain** with distinct auth, rather than a path under the public app (path-based restrictions are bypass-prone)?

## Static signals
Spring Boot Actuator — overly broad exposure:
- `management.endpoints.web.exposure.include: '*'` (or `include: '*'\n  exclude:` empty) — exposes all endpoints
- `management.endpoint.shutdown.enabled: true`
- `management.server.port` absent or equal to the app port (no port separation)
- `endpoints.shutdown.enabled: true` (Spring Boot 1.x legacy)

Django / Python:
- `DEBUG = True` in settings shipped to production
- `django.contrib.admin` in `INSTALLED_APPS` with no `admin.site.login` MFA and no URL gating
- Flask `app.run(debug=True)` or `app.debug = True` exposing the Werkzeug debugger (`/console`)
- FastAPI `debug=True` or Swagger/ReDoc (`/docs`, `/redoc`) left enabled in production

Node / JavaScript:
- Routes mounting `/admin` with only a weak/bypassable check: `app.use('/admin', (req,res,next) => req.query.token === 'secret' ? next() : res.redirect('/'))`
- Express `app.use('/admin', adminRouter)` with no auth middleware attached
- Strapi, Directus, or Ghost admin UIs exposed without env-gated admin account
- `NODE_ENV !== 'production'` branches that mount debug/dev routes

Java / JVM:
- Jolokia (`/jolokia`) exposed without auth → JMX RCE
- JNDI/JMX remote ports (`com.sun.management.jmxremote.port`) bound to all interfaces
- Tomcat `/manager/html`, `/host-manager` with default `tomcat/tomcat` creds
- H2 console: `spring.h2.console.enabled=true` + `path=/h2-console`

Go / Rust / .NET:
- Go `net/http/pprof` registered on the default mux (`http.DefaultServeMux`) — `/debug/pprof/` reachable, leaks goroutines/heap
- ASP.NET `/health` combined with Diagnostics `/diagnostics`, ELMAH `/elmah.axd`, or `UseDeveloperExceptionPage()` in production
- Actuator-like libs (e.g. Steeltoe) exposing env/config endpoints

PHP / Ruby / others:
- phpMyAdmin, Adminer, phpPgAdmin webroot-deployed with no auth proxy
- Rails `/admin` engine or ActiveAdmin with `http_basic_authenticate_with` using a weak/shared password
- WordPress `wp-admin` with default `admin` account and weak password

## False positives
- The management interface is bound to a private/loopback interface (`127.0.0.1`), behind a VPN, or gated by an IP allow-list **and** MFA — confirm via security group / ingress rules, not just code.
- Actuator exposes only `health` (no detail) and `info`, both on a separate management port requiring auth — `management.endpoints.web.exposure.include: health` with `show-details: never` is safe.
- The "admin" path is a marketing/CMS page with no privileged actions (no user/secret/config management) — verify there are no destructive handlers behind it.
- DB consoles are present in a Docker Compose dev file (`docker-compose.override.yml`) but not in the production deployment manifest — check the prod compose/k8s manifests.
- Swagger is intentional for a public API and contains no internal/sensitive operations.

## Attack scenario
1. Reconnaissance: attacker probes `https://app.example.com/actuator`, `/h2-console`, `/admin`, `/debug/pprof`, `/console` via a directory-buster or known-path list.
2. `/actuator/env` returns 200 with the full environment, including `SPRING_DATASOURCE_PASSWORD`, `JWT_SECRET`, and cloud provider credentials.
3. `/actuator/heapdump` is enabled — attacker downloads the JVM heap and greps it for in-memory tokens and decrypted secrets.
4. Using the leaked DB credentials, the attacker connects to the database (if also exposed) or pivots: `/actuator/refresh` (Spring Cloud) reloads config; `/actuator/shutdown` (if enabled) causes an outage.
5. Alternatively, `/h2-console` is open with the default empty `sa` password — attacker creates an `ALIAS` Java function and executes arbitrary OS commands on the host.
6. Result: full remote code execution / data exfiltration / DoS, from a single unauthenticated GET request.

## Impact
- **Confidentiality**: environment variables, DB credentials, signing keys, cloud IAM keys, and in-memory session tokens exposed via `env`/`heapdump`; full data breach.
- **Integrity**: admin actions let an attacker create/modify accounts, alter application config, push malicious code via refresh/deploy endpoints.
- **Availability**: `shutdown`, `pause`, or `refresh` endpoints enable instant denial of service; DB console access allows destructive queries.
- Severity is effectively **critical** whenever a sensitive management endpoint is unauthenticated on a public interface — a single request yields full compromise. It scales down to low/info when only a non-sensitive `health` indicator is exposed.

## Remediation
Minimize exposure and isolate the management plane on a separate, authenticated, network-restricted surface:
```yaml
# VULNERABLE — all Actuator endpoints on the public port, no auth
management:
  endpoints:
    web:
      exposure:
        include: '*'
  endpoint:
    shutdown:
      enabled: true

# SAFE — minimal exposure, separate port, auth required
management:
  server:
    port: 9090                       # internal-only; firewalled off from the Internet
    addresses: 127.0.0.1             # or a private subnet
  endpoints:
    web:
      exposure:
        include: health              # only what the load balancer needs
  endpoint:
    health:
      show-details: never            # do not leak dependency/stack info
    shutdown:
      enabled: false
spring:
  h2:
    console:
      enabled: false                 # never in production
```
Add defense-in-depth: enforce MFA on every admin login, run management interfaces on a distinct subdomain behind an authenticated reverse proxy with an IP allow-list, and disable all debug consoles (`DEBUG=False`, Swagger off, `pprof` unregistered) in production builds.

## References
- OWASP ASVS V14.x — Configuration and architecture (build/deploy, admin interfaces, environment hardening)
- OWASP WSTG-CONF-05 — Review Old Backup and Unreferenced Files for Sensitive Information (admin consoles left deployed)
- OWASP WSTG-CONF-11 — Test Cloud Storage (exposed management assets) / Admin interface testing
- OWASP Cheat Sheet: Administration Cheat Sheet
