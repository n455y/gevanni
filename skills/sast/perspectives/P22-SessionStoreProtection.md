---
id: P22
name: SessionStoreProtection
area: V7 Session Management
refs: ASVS V3.1.x, V8.1.x / WSTG-SESS-08 / CS: Session Management
requires: [backend]
---

# P22 — SessionStoreProtection

## Overview
Server-side session state (Redis, Memcached, a database table, or in-memory maps) and the secrets bound to it are the crown jewels of authentication: whoever can read or forge a session effectively bypasses login. The issue is that session payloads and their backing store are frequently left unauthenticated, unencrypted, or over-privileged — a plaintext credential stuffed into the session object, an open Redis `6379`, a DB column of session blobs with no integrity protection, or a client-side cookie store signed with a weak/guessable secret. The root cause is almost always treating session storage as an internal, implicitly-trusted component rather than as a secret store that must be encrypted in transit and at rest, access-controlled, and integrity-protected. Once the store is exposed (a misconfigured cloud snapshot, an SSRF that reaches the cache port, a SQL-injection that dumps the sessions table), every active session becomes a takeover primitive.

## What to check
- Is the session **store connection** authenticated and TLS-encrypted? Redis without a password/ACL, Memcached with no SASL, or a DB session table reached over a plaintext link is a direct path to session theft.
- Is session data stored **encrypted at rest**? A Redis RDB/AOF dump, an EBS volume, or a DB column holding plaintext session blobs must be encrypted (disk encryption + column-level if it contains PII).
- Does the application put **secrets or PII into the session payload** — passwords, API keys, OAuth tokens, full SSNs, card data, raw credentials? Sessions should hold only an opaque identifier (the user id) and reference everything else by id, never inline it.
- For **client-side / cookie stores** (Express `cookie-session`, Rails `cookie_store`, Django signed-cookie backend, Gorilla securecookie, JWT in a cookie): is the cookie signed with a **strong, high-entropy secret** (not a default, not `secret`, not checked into source) and is integrity tampering detected? Is the cookie marked `HttpOnly`, `Secure`, and `SameSite`?
- Is the session store **shared across tenants/services** without per-tenant namespacing or ACLs, allowing one tenant to read another's sessions?
- Are **expired/invalidated sessions actually purged** from the store on logout, or do they linger until natural expiry (allowing reuse of a stolen-but-revoked session)?
- Does the app rely on **in-memory session stores** (`express-session` default `MemoryStore`, a global `Map`) that leak on any memory dump, are invisible to ops, and are unscalable — and is this shipped to production?
- Is the **session id** generated with a CSPRNG and long enough (≥128 bits)? A weak or sequential id lets an attacker guess/brute-force other sessions directly from the store key.

## Static signals
Secrets/PII stored in the session payload:
- Node: `req.session.password = ...`, `req.session.token = user.apiKey`, `ctx.session.user = user` (whole user object incl. password hash)
- Python (Flask): `session['oauth_token'] = token`, `session['user'] = user.__dict__`
- Python (Django): `request.session['pw'] = ...`, `request.session['profile'] = user.__dict__`
- Ruby/Rails: `session[:user_token] = ...`, `session[:user] = user.attributes`
- Java (Spring): `session.setAttribute("token", jwt)`, `session.setAttribute("user", userEntity)`
- Go: `session.Values["token"] = token`; `sessions.Save(r, w)`
- PHP: `$_SESSION['password'] = ...`, `$_SESSION['api_key'] = ...`

Insecure / unauthenticated store connection:
- Node: `new Redis({ host })` with no `password`/`tls`; `createClient({ url: 'redis://...' })` (plain `redis://` not `rediss://`)
- Python: `redis.Redis(host=...)` no `ssl=True`/`password`; `pymemcache.Client((host,11211))`
- Java: `jedis = new Jedis(host)` no auth; Spring `@EnableRedisHttpSession` without TLS config
- Go: `redis.NewClient(&redis.Options{Addr: ...})` no TLS/password

Client-side cookie store with weak/missing signing:
- Node: `const session = require('cookie-session')({ keys: ['secret'] })` — short/guessable keys array; Express `session({ secret: 'keyboard cat' })`
- Rails: `Rails.application.config.secret_key_base` default/short; `cookies.signed[:x]`
- Django: signed-cookie session backend without a strong `SECRET_KEY`
- Go (Gorilla): `securecookie.New(hashKey, blockKey)` with `hashKey == nil` (unsigned) or short

In-memory / non-production store:
- Node: `app.use(session({ store: undefined }))` or `new MemoryStore()` shipped to prod
- Python: Flask default `werkzeug` FilesystemSession but pointing at `/tmp`; or a hand-rolled `SESSIONS = {}` dict

## False positives
- The store is Redis with **ACL + TLS + at-rest encryption** (e.g. AWS ElastiCache encryption-in-transit + at-rest, or a managed Redis with auth), and the connection string uses `rediss://` with credentials from a secret manager — well protected, skip.
- The session payload contains **only an opaque user id / role flags**, no secrets or PII, and the id is unguessable — this is the recommended design, not a finding.
- Cookie store is signed with a **32+ byte CSPRNG secret** stored in a secret manager (env var injected at deploy), with `HttpOnly; Secure; SameSite` set, and the integrity algorithm is current (HMAC-SHA256+, AES-GCM) — acceptable.
- In-memory store is used only in **test/dev code** gated by `NODE_ENV === 'test'` or a test fixture — not a production concern.
- A JWT in a cookie is acceptable when it is **signed (and encrypted, JWE, if it carries claims)** with a strong key, short-lived, and rotated — flag only if unsigned (`alg: none`), weakly signed, or carrying secrets.

## Attack scenario
1. Reconnaissance: the attacker finds an open Redis (`6379`) or Memcached (`11211`) exposed to the internet (or reachable via SSRF from inside the network), or obtains a DB read via SQL injection.
2. They dump the session keyspace: `KEYS sess:*` / `GET sess:<id>` (Redis), or `SELECT session_data FROM sessions` (DB), recovering active session blobs — many of which store `user_id`, role, and sometimes an inline OAuth/access token.
3. They replay the stolen session cookie/id against the app. Because the id is opaque to the app, the server trusts it and authenticates them as the victim — no password needed.
4. If the store held an inline access token (`session.token`), they exfiltrate it for API access beyond the session. If the cookie store was signed with a weak/default secret, they instead **forge** a cookie granting admin (`{ uid: 1, role: 'admin' }`) without ever touching the store.
5. Persistence: sessions are not purged on logout, so the window is the full idle/lifetime timeout — hours to days.

## Impact
- **Confidentiality**: full disclosure of every active session and any inline PII/secrets; theft of OAuth/access tokens.
- **Integrity**: session hijacking/fixation → actions performed as any user, privilege escalation if admin sessions or forgeable cookies are involved. Account takeover.
- **Availability**: an attacker able to write the store can mass-invalidate/corrupt sessions, forcing global logout.
- Severity scales with what the store holds: opaque ids only → session-hijack risk; inline tokens/credentials → credential-theft-grade breach. A forgeable client-side cookie store with a weak secret is effectively **unauthenticated admin access** and is Critical.

## Remediation
Keep secrets out of the session; protect the store in transit and at rest:
```ts
// VULNERABLE — secret in session, unsigned cookie, plaintext Redis
req.session.password = user.password;
app.use(session({ secret: 'keyboard cat', store: undefined })); // MemoryStore + weak secret
const client = new Redis({ host: 'cache' }); // no auth, no TLS

// SAFE — opaque id only, strong secret, TLS+ACL Redis, cookie flags
app.use(session({
  name: '__Host-sid',
  store: new RedisStore({ client: tlsRedisClient }), // rediss:// + ACL user
  secret: process.env.SESSION_SECRET,                 // 32+ bytes, CSPRNG, from secret manager
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 1000 * 60 * 30 },
}));
req.session.uid = user.id; // id reference only — never the password/token
```
As defense-in-depth: purge sessions on logout and re-key the signing secret on incident, rotate the session id after privilege change (login/role elevation), and segment multi-tenant stores by key prefix + per-tenant ACLs so one tenant cannot enumerate another's sessions.

## References
- OWASP ASVS V3.1.x — Session generation, V8.1.x — Data protection / secrets not stored unnecessarily
- OWASP WSTG-SESS-08 — Testing for Session Puzzling / Session Fixation / Store Exposure
- OWASP Cheat Sheets: Session Management, Authentication, Database Security, Transport Layer Protection
