---
id: P8
name: AuthRateLimit
area: V6 Authentication
refs: ASVS V2.5.x / WSTG-ATHN-04, WSTG-ATHN-10 / CS: Authentication, Blocking Brute Force Attacks
---

# P8 — AuthRateLimit

## Overview
Authentication endpoints that accept credentials — login, sign-in, token issuance, password reset, MFA verification — are prime targets for brute-force and credential-stuffing attacks. Without per-user and per-IP rate limiting, account lockout, progressive delays, or CAPTCHA challenges, an attacker can submit unlimited guesses at full speed. The root cause is usually a missing throttle on the auth route, a global limiter that does not specifically cover login, or a lockout counter that was never implemented. The defense must be layered: throttling slows automation, lockouts/delays raise cost per guess, and MFA caps the value of any single cracked password.

## What to check
- Does every credential-accepting endpoint (`/login`, `/signin`, `/token`, `/oauth/token`, `/reset-password`, `/verify-otp`, `/mfa`) have an explicit throttle or lockout mechanism — not just a global limiter?
- Is the limit applied **per-identity (username/email)** in addition to per-source IP? Per-IP alone fails behind NAT/CDNs and is bypassable via rotating proxies.
- Is there an attempt counter with a lockout threshold (e.g. lock or require CAPTCHA after N failed attempts within a window)? Is the counter reset only on *successful* login, not on failed?
- Does failed-login handling introduce a **timing or progressive delay** (sleep, work factor, uniform response time) to slow online guessing and avoid user enumeration?
- Is CAPTCHA or exponential backoff triggered after repeated failures from the same identity/IP?
- Are responses to failed login **identical** regardless of whether the username exists (no "user not found" vs "wrong password" distinction, no timing oracle)?
- Does the throttle survive distributed attempts (rate-limit store backed by Redis/shared cache, not in-process memory that resets per instance)?
- Are password reset / OTP endpoints rate-limited to prevent enumeration and SMS/email bombing?
- Is login throttling logged and alertable (bursts of failures from one IP = active attack)?

## Static signals
No throttle/limiter imported or applied on auth routes:
- Node/Express: `app.post('/login', (req,res) => auth(req.body))` — no `rateLimit` middleware in the chain
- NestJS: controller/handler lacking `@Throttle(...)` and no global `ThrottlerGuard` covering auth
- Python/Flask: route without `@limiter.limit(...)` (Flask-Limiter) or `@retry`/lockout decorator
- Python/Django: `django-axes` / `django-ratelimit` absent; `django.contrib.auth.login` with no `AXES_*` settings
- Python/FastAPI: endpoint missing `@limiter.limit(...)` (slowapi) on `/token`
- Java/Spring: no `spring-boot-starter-bucket4j` / filter, `SecurityConfig` without rate-limit or `AuthenticationFailureHandler` lockout
- Go: handler `http.HandleFunc("/login", loginHandler)` with no `tollbooth`/`golang.org/x/time/rate` wrapper
- Ruby/Rails: `rack-attack` not configured, no `Rack::Attack.throttle` rule for `/sign_in`
- PHP/Laravel: no `throttle:` middleware on `Route::post('/login', ...)` (Laravel's default `throttle:5,1` is often stripped for API auth)

Lockout / attempt-counter logic absent — grep for:
- Missing: `attempts`, `failed_attempts`, `lockout`, `locked_until`, `login_attempts`, `throttle_key`
- Redis key patterns absent: `rl:login:{ip}`, `rl:login:{user}`, `fails:{user}`

Limiter present but **misconfigured**:
- Only `app.use(rateLimit(...))` globally with no per-route override for login
- `skip: () => true` or `skipSuccessfulRequests` misused on auth routes
- In-process `Map()` store (single-instance leak under horizontal scaling)

## False positives
- A layered WAF / API gateway / reverse proxy (Cloudflare, AWS WAF, nginx `limit_req`) enforces login throttling upstream before traffic reaches the app. Confirm the rule actually targets the login path and is keyed on username or has bot-protection.
- Auth is delegated to an IdP (Auth0, Cognito, Okta, Keycloak) whose built-in brute-force protection and breach-password checks are enabled — verify in the IdP dashboard, not the app code.
- A proof-of-work or WebAuthn/passkey flow makes online guessing infeasible by design (no shared secret to brute-force).
- The endpoint uses short-lived, single-use signed links (magic link) rather than passwords — brute-force is not the relevant threat, though request bombing still needs limiting.
- Global limiter with a strict, auth-specific window (e.g. 5/min keyed on the credential field) is acceptable even without a dedicated library, if it actually covers the login route.

## Attack scenario
1. Attacker harvests a credential-stuffing list (email/password pairs from a breached site) or targets one known username with a password wordlist.
2. The login endpoint has no throttle; the attacker fires 1000s of requests/sec from a rotating proxy pool.
3. Per-IP limiting is bypassed because each request comes from a fresh exit IP; per-user limiting is absent.
4. For each matching credential the attacker receives a session token, takes over the account, and pivots to password reset / linked services.
5. If responses distinguish "user not found" from "wrong password", the attacker concurrently enumerates valid usernames for a second pass.

## Impact
- **Confidentiality**: account takeover — full access to the victim's data, messages, payment methods.
- **Integrity**: fraudulent transactions, email/setting changes, privilege abuse if an admin or support account falls.
- **Availability**: targeted lockouts can DoS a single user (user-enumeration DoS) if lockout is overly aggressive and unsupervised.
- Severity scales with the data value of compromised accounts and with whether MFA is enforced: no throttle + no MFA on a high-value app = Critical; throttle present but MFA absent = High; both present = Low/Medium residual.

## Remediation
Apply a dedicated, layered throttle on every credential endpoint — keyed on both identity and IP, backed by a shared store:
```ts
// VULNERABLE — unlimited guesses
app.post('/login', (req, res) => auth(req.body));

// SAFE — per-route limiter keyed on username + IP, shared store
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisStore({ client: redis }),       // survives multi-instance
  keyGenerator: (req) => `${req.ip}:${req.body?.username}`,
  handler: (req, res) => res.status(429).json({ error: 'too_many_attempts' }),
});
app.post('/login', loginLimiter, (req, res) => auth(req.body));
```
Pair throttling with uniform error responses and a constant-time failed-login path to prevent user enumeration, and enforce MFA + breached-password checks as defense-in-depth so that even a cracked password yields no access.

## References
- OWASP ASVS V2.5.x — Authentication throttling and observability requirements
- OWASP WSTG-ATHN-04 (Testing for Bypassing Authentication Schema), WSTG-ATHN-10 (Testing for Brute Force / Weak Lock Out)
- OWASP Cheat Sheets: Authentication, Blocking Brute Force Attacks
