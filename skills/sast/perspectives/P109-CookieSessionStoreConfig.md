---
id: P109
name: CookieSessionStoreConfig
area: V13 Configuration
refs: ASVS V3.3.x, V14.x / WSTG-SESS-02, WSTG-SESS-07 / CS: Session Management, Cookie Security
---

# P109 — Cookie Session Store Config

## Overview
Server-side session stores and the cookies that carry their session IDs are only as safe as the **global configuration** that wires them up: the signing/encryption secret, the cookie attributes (`Secure`, `HttpOnly`, `SameSite`, expiry), and the backing store's own transport and authentication. A single weak `secret` lets an attacker forge or tamper with session cookies (forgotten `secret`-based sessions, signed-cookie abuse), a missing `Secure` flag leaks the credential over HTTP, and an unauthenticated/plaintext Redis or DB connection exposes the entire session table. The root cause is almost always a development default that was never hardened for production — `secret: 'keyboard cat'`, `MemoryStore`, `cookie: { secure: false }`, or a store URI without TLS/AUTH. This perspective is the *configuration* layer; per-attribute issues belong to P17-SessionCookieAttributes and store hardening specifics to P22-SessionStoreProtection.

## What to check
- Is the session signing/encryption `secret` long (>=128 bits of entropy), unique per environment, loaded from a secret manager (env var / KMS), and rotated — **not** a hardcoded literal, default, or reused value?
- Are all cookie attributes locked to the secure side globally: `Secure: true`, `HttpOnly: true`, `SameSite: 'Lax'`/`'Strict'` (or `'None'`+`Secure` only with explicit cross-site justification), and `maxAge`/`expires` bounded?
- Is the production session **store** an external, shared, durable store (Redis, DB) with TLS in transit (`rediss://`, `tls:` option) and authentication (`AUTH` password / ACL user) — not `MemoryStore`/in-process/in-file in `tmp`?
- Does the store connection pool enforce a TLS certificate/CA check (no `rejectUnauthorized: false`), and does it fail closed if the secret or store env var is missing?
- Is session ID regeneration on authentication/privilege change enabled (`regenerate`), and is the global session secret protected against rotation invalidation (keyring/multiple secrets)?
- Are cookieless sessions, signed-cookie-only sessions (no server state), and JWT-in-cookie schemes treated as the same risk class (signature secret strength, `__Host-` prefix)?
- Does the config differ between dev and prod (NODE_ENV gate), with dev secrets never shipped to prod?

## Static signals
Hardcoded / weak secrets (Node/Express):
- `session({ secret: 'keyboard cat' })`, `secret: 'secret'`, `secret: 'changeme'`, `secret: process.env.npm_package_name`
- `app.use(cookieSession({ keys: ['key1'] }))` (signed-cookie session, short/known key)
- `app.set('trust proxy', false)` with `Secure` cookies behind a TLS-terminating proxy (cookies dropped)

Missing/insecure cookie attributes:
- `cookie: { secure: false }`, `httpOnly: false`, `sameSite: undefined`/`sameSite: 'none'` without `secure`
- Express `res.cookie('sid', v, { httpOnly: false })`; Django `SESSION_COOKIE_SECURE = False`, `CSRF_COOKIE_HTTPONLY = False`; Rails `config.force_ssl = false`

Dangerous store choices:
- `express-session` with **no `store` option** → defaults to `MemoryStore` (not for production; leaks memory, no cross-process, DoS-friendly)
- `new MemoryStore()`, `new FileStore({ path: '/tmp' })`, `fs.writeFileSync` of session blobs
- Store URIs without TLS/AUTH: `redis://host:6379` (no `rediss://`, no `:password@`), `connect-redis` with unauthenticated client

Python:
- Django `SECRET_KEY = 'dev'` / hardcoded; `SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'` with weak key; `SESSION_COOKIE_AGE` huge
- Flask `app.secret_key = 'dev'`; `SESSION_COOKIE_SECURE = False`; `SESSION_TYPE = 'filesystem'` in `/tmp`
- FastAPI/Starlette `SessionMiddleware(secret_key='...')` with short constant

Java:
- Spring `server.servlet.session.cookie.secure=false`, `cookie.http-only=false`; `spring.session.store-type=hash-map` (in-memory); JDBC session over plain JDBC URL
- Tomcat `Context` with `cookies=true` and no `Secure` on `<Connector>`

Go / Ruby / PHP:
- Go `gorilla/sessions` with `sessions.NewCookieStore([]byte("..."))` short key, or filesystem store with no cleanup
- Rails `config.session_store :cookie_store, key: '_app_session'` without `secure: true`; `secret_key_base` hardcoded/short
- PHP `session.save_handler = files`, `session.cookie_secure = 0`, `session.cookie_httponly = 0`, `session.save_path = "/tmp"`; Laravel `SESSION_DRIVER=file`, `SESSION_SECURE_COOKIE=false`

TLS/cert verification disabled:
- `rejectUnauthorized: false`, `InsecureSkipVerify: true`, `tls.Config{ InsecureSkipVerify: true }`, `verifyPeer: false` on the store client

## False positives
- Strong per-env secret from a secret manager + `Secure`/`HttpOnly`/`SameSite` attributes set + an authenticated, TLS-protected Redis/DB store → compliant. Verify each layer, not just the presence of a store option.
- `MemoryStore` or `secret: 'dev'` gated strictly behind `NODE_ENV !== 'production'` / `DEBUG` / a test harness with no real users.
- Missing `Secure` flag when the app is reachable **only** over TLS at the network boundary and `trust proxy` is correctly set so the flag is emitted — but flag it as fragile; prefer explicit `Secure`.
- Signed-cookie sessions (`cookieSession`) where the key is >=256 bits, rotated, and the design intentionally carries no server state with sensitive data excluded.
- `SameSite=None; Secure` set deliberately for a documented cross-site SSO/embed flow, with CSRF mitigations applied.

## Attack scenario
1. Reconnaissance: the attacker notices the app sets `_app_session` without `Secure` and the signing secret is the well-known demo value `keyboard cat` (leaked in a public repo / docs).
2. Over a hostile network (rogue Wi-Fi, downgraded HTTP endpoint) the attacker captures a victim's session cookie; or, using the known secret, forges a cookie that deserializes/encrypts to an admin session ID.
3. If the store is an unauthenticated plaintext Redis (`redis://`, no ACL), the attacker who can reach the host directly enumerates keys (`KEYS *`) and reads/rewrites session blobs — granting any user's session.
4. The attacker operates as the victim (or admin), bypassing authentication entirely; because the secret is static and unrotated, forgery works until deployment.

## Impact
- **Confidentiality**: full session/credential disclosure, account takeover of arbitrary users; with a forgeable secret, complete impersonation of any identity including admins.
- **Integrity**: attacker-authored session state, privilege escalation, persisted malicious data in the store.
- **Availability**: `MemoryStore` exhaustion and unbounded store growth enable trivial DoS; a leaked/rewritten store can corrupt sessions service-wide.
- Severity scales with the data in the session (roles, PII) and the breadth of the store compromise — a single weak secret is often **total application compromise**.

## Remediation
Load the secret from a secret manager, force every cookie attribute to the secure side, and use an authenticated, TLS-protected external store:
```ts
// VULNERABLE — weak literal secret, default MemoryStore, insecure cookie flags
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }, // + no store => MemoryStore
}));

// SAFE — strong env secret, TLS+AUTH Redis store, hardened cookie attributes
const RedisStore = require('connect-redis')(session);
const redisClient = require('redis').createClient({
  url: process.env.REDIS_TLS_URL,            // rediss://...:password@
  socket: { tls: true, rejectUnauthorized: true },
});
app.use(session({
  name: '__Host-sid',
  secret: process.env.SESSION_SECRET,         // >=128-bit, from secret manager
  store: new RedisStore({ client: redisClient }),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    secure: true, httpOnly: true, sameSite: 'lax',
    maxAge: 30 * 60 * 1000, path: '/', // __Host- prefix requires path=/ + no Domain
  },
}));
app.set('trust proxy', 1); // emit Secure behind TLS-terminating proxy
```
As defense-in-depth, rotate secrets via a keyring (multiple active secrets), enforce `regenerate()` on login/privilege change, and alert on `NODE_ENV=production` with `MemoryStore` or a missing secret env var.

## References
- OWASP ASVS V3.3.x — Session management (timeout, regeneration, token quality); V14.x — Configuration & architecture (secrets, transport)
- OWASP WSTG-SESS-02 (Testing for Cookies Attributes), WSTG-SESS-07 (Testing Session Timeout), WSTG-SESS-03 (Session Schema / store hardening)
- OWASP Cheat Sheets: Session Management, Cookie Security, Transport Layer Protection
