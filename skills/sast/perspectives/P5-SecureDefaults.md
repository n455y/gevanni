---
id: P5
name: SecureDefaults
area: V15 Secure Coding and Architecture
refs: ASVS V1.5.x / V14.x / WSTG-CONF-02 / CS: Architecture Cheat Sheet
requires: []
---

# P5 — SecureDefaults

## Overview
Secure defaults (the "secure by default" principle, ASVS V1.5) means every newly created user, object, session, or configuration starts in its most restrictive state and privileges must be **opt-in, not opt-out**. The root cause of related breaches is almost always a permissive default that an operator or user was expected to tighten but never did: a fresh account ships as `admin`, a new document is world-readable, cookies ship without `Secure`, or CORS ships as `origin:'*'`. Defaults are sticky — once a thousand users have been provisioned the wrong way, the fix becomes a migration rather than a config change. The defensive goal is "fail closed": if a setting is forgotten, the worst outcome is a broken feature, not a compromise.

## What to check
- What is the default role/scope for a newly created user or service principal? Is it `admin`/`superuser`/`write` instead of an unprivileged role requiring explicit elevation?
- Are new resources (files, objects, API keys, tokens, calendar entries, notes) created with `visibility: 'public'` or `private: false` unless the caller explicitly opts in to sharing?
- Do security-sensitive framework options default to the safe side? Cookies without `secure`/`httpOnly`/`sameSite`, sessions without rotation, passwords with no hashing or a weak algorithm, CSRF disabled, TLS verification disabled.
- Does CORS ship as `origin: '*'` (or `Access-Control-Allow-Origin: *` with credentials) by default? Is `helmet`/equivalent security headers middleware present and not disabled?
- Are error/debug responses verbose by default (stack traces, internal IPs, SQL fragments, `DEBUG=True`)?
- Are ports/binds permissive by default — listening on `0.0.0.0` instead of `127.0.0.1`, or HTTP (no TLS) on production endpoints?
- Are default credentials (e.g. `admin/admin`) seeded for first-run, and is there forced rotation on first login?
- For feature flags, is the dangerous toggle (e.g. "skip MFA", "allow signup without verification") default-off?

## Static signals
Over-permissive role defaults:
- Node/TS: `User.create({ ...body, role: 'admin' })`, `role: Role.ADMIN`, `isAdmin: true`
- Python: `User.objects.create(role='admin')`, `default='admin'` on a role field, `is_superuser=True`
- Ruby: `User.create!(role: :admin)`, `default: :admin` in migrations
- Java: `new User(...).setRole("ROLE_ADMIN")`, `@Column(defaultValue="admin")`
- Go: `&User{Role: "admin"}`, `default:"admin"` struct tag

Public visibility / sharing defaults:
- `visibility: 'public'`, `isPublic: true`, `private: false`, `shared: true` in object creation
- ORM field `default='public'`, `default=True` for an `is_public` boolean
- S3: `ACL='public-read'`, `public-read-write`; pre-signed URLs with long/default expiry

Insecure framework defaults:
- `cors({ origin: '*'', credentials: true })`, `Access-Control-Allow-Origin: *` paired with credentials
- `cookie: { secure: false }`, `httpOnly: false`, `sameSite: 'none'` without `secure`
- `app.debug = True` / `DEBUG=True` / `DEBUG = env('DEBUG', True)` (default-on)
- `verify=False`, `check_hostname=False`, `InsecureSkipVerify: true` (TLS verification off)
- `host: '0.0.0.0'` for an internal admin/management service
- `JWT.verify(token, secret, { algorithms: ['none'] })` accepting `alg: none`

Verbose / leaking error defaults:
- `app.use(errorhandler())` or `SHOW_ERRORS=true` in production
- Django `DEBUG=True` shipped to prod; Spring Boot `server.error.include-stacktrace=always`
- `console.log(err.stack)`, `return res.status(500).send(err)` returning raw errors to clients

Default / seeded credentials:
- `admin/admin`, `password`, hard-coded `DEFAULT_PASSWORD = 'changeme'`, `seed!(email: 'admin@', password: 'password')`
- Empty secret keys generated at first run and never rotated: `SECRET_KEY = ''` or a static placeholder

## False positives
- A genuinely public resource (marketing site, public docs, a read-only public API, or an anonymous "explore" feed) where world-readable is the intended product behavior — confirm the resource carries no PII or per-user data.
- A permissive default that is immediately overridden before the object is persisted (e.g. a builder that starts broad then narrows) — trace to the final saved state, not the intermediate.
- An internal-only service bound to `0.0.0.0` but reachable only on a firewalled private network with no ingress — note it as defense-in-depth, not a finding.
- An intentionally disabled security header in dev/test config that has a separate prod config enforcing it (`helmet()` enabled in prod middleware, `DEBUG=False` in prod env).
- Seeded admin accounts that are auto-flagged for forced password change on first login and cannot be used until rotated.

## Attack scenario
1. The application creates every new user with `role: 'admin'` because the default role field reads from an unchecked `req.body.role`.
2. An attacker self-registers a normal account via the public signup endpoint.
3. Because the default role is `admin`, the attacker's freshly created account has full administrative privileges with no elevation workflow.
4. The attacker uses the admin panel to read all other users' data, export the database, or create a second persistent backdoor account — all without ever needing to exploit a second vulnerability.

## Impact
- **Confidentiality**: a default-public resource leaks data to anyone (or any authenticated user) who enumerates it; default-admin accounts grant full data access.
- **Integrity**: default-admin/over-scoped roles allow unauthorized modification or deletion of records and config.
- **Availability**: default-on debug modes, verbose errors, and permissive CORS enable information leakage that supports further attacks (DoS amplification, account takeover, mass enumeration).
- Severity scales sharply with the resource: a public-read note is a low finding; a default-admin role or default-public database backup is critical and often means immediate full compromise.

## Remediation
Default to least privilege at the data model; require explicit elevation through a separate, audited flow:
```ts
// VULNERABLE — new users become admins; visibility is world-readable
const user = await User.create({ ...req.body, role: 'admin', visibility: 'public' });

// SAFE — minimal default role, private by default; elevation is a distinct flow
const role = ALLOWED_SIGNUP_ROLES.includes(req.body.role) ? 'user' : 'user';
const user = await User.create({ ...req.body, role, visibility: 'private' });
```
Layer defense-in-depth: enable `helmet()`/security headers, `cors` with an explicit allow-list, `secure`/`httpOnly`/`sameSite=lax` cookies, `DEBUG=False` and stripped error responses in prod, and forced first-login password rotation. Verify defaults via tests (assert a freshly created user/role/visibility) so a regression fails CI rather than reaching prod.

## References
- OWASP ASVS V1.5 — Architecture: secure defaults and least privilege
- OWASP ASVS V14.x — Configuration: verify that defaults are secure
- OWASP WSTG-CONF-02 — Test Application Platform Configuration
- OWASP Cheat Sheet: Architecture Cheat Sheet, OS Command Injection Defense (defaults/context), Content Security Policy
