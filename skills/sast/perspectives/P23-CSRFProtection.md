---
id: P23
name: CSRFProtection
area: V7 Session Management
refs: ASVS V3.x / WSTG-SESS-04, WSTG-INPV-12 / CS: Cross-Site Request Forgery Prevention
requires: [backend]
---

# P23 — CSRF Protection

## Overview
Cross-Site Request Forgery (CSRF) occurs when a state-changing request (POST/PUT/DELETE/PATCH) relies solely on an ambient credential — typically the session cookie automatically attached by the browser — and the server performs the action without any secondary proof that the request was **intentionally issued from the application's own UI**. The root cause is the browser's automatic attachment of cookies cross-origin combined with the absence of an un-forgeable, request-bound token, an `Origin`/`Referer` check, or a `SameSite` cookie restriction. The attacker never sees the cookie; they only induce the victim's browser to issue a forged request (a hidden auto-submitting form, a `fetch` from a malicious page, or an `<img>` tag for simple GETs). CSRF lets an attacker act *as* the victim within the victim's privilege level — transferring funds, changing the password/email, deleting data, or elevating an account — without ever needing to steal credentials.

## What to check
- For every state-changing endpoint (POST, PUT, PATCH, DELETE — and any GET that mutates state), is a CSRF defense enforced **server-side**? Client-side token checks alone are bypassable.
- If a synchronizer (anti-CSRF) token is used, is it validated on the server for every state-changing request, scoped to the user session, rotated on login/logout, and rejected on mismatch (not silently dropped)?
- Is the token transmitted in a header or form field (not solely in a `SameSite=None` cookie that a cross-site context could read) and bound to a session identifier (to prevent a token from one account being replayed against another)?
- Are session cookies set with `SameSite=Lax` or `SameSite=Strict`? If `SameSite=None`, is `Secure` set and is an independent token/Origin check present? (`Lax` only defends cross-site POSTs, not top-level GET navigations or sub-resource requests — GET-based state changes remain vulnerable.)
- Is the `Origin` and/or `Referer` header validated against an allow-list for state-changing requests, with absent/blank headers rejected (browsers always send `Origin` on cross-origin POSTs and `Referer` on same-origin requests)?
- Are login endpoints protected (login CSRF — forging authentication against the attacker's account, enabling session-fixation / credential theft later)?
- For cookie-based auth APIs, is there a defense at all? If auth is purely `Authorization: Bearer <token>` (header, not cookie), CSRF does not apply — but verify the token isn't *also* accepted via cookie.
- Are CORS rules overly permissive (`Access-Control-Allow-Origin: *` with credentials, or reflected-echo of `Origin` with `Allow-Credentials: true`)? This widens CSRF / cross-site read exposure.
- Multi-step flows (setup confirmations, password change, 2FA disable): does each step require its own token, or can a single forged request skip to the final state-changing step?

## Static signals
Missing or disabled CSRF middleware on state-changing routes:
- Node/Express: no `csurf`/`csrf-csrf`/`@fastify/csrf` in dependencies; routes like `app.post('/transfer', (req,res) => ...)` with no middleware
- Django: `MIDDLEWARE` lacking `'django.middleware.csrf.CsrfViewMiddleware'`, or `@csrf_exempt` on a mutating view, or `CsrfViewMiddleware` removed globally
- Flask: no `flask_wtf.csrf.CSRFProtect` / `WTF_CSRF_ENABLED = False`
- Rails: `protect_from_forgery` absent or `skip_before_action :verify_authenticity_token`, `skip_forgery_protection`
- Spring (Java): no `CSRF` filter in `SecurityFilterChain` / `http.csrf().disable()`, missing `CsrfFilter`
- ASP.NET: `[IgnoreAntiforgery]`, `AntiForgeryConfig.SuppressXFrameOptions`, or antiforgery filter removed
- Laravel: `VerifyCsrfToken` middleware removed from the `$middlewareGroups['web']`, or route listed in `$except`
- Go (net/http): handler mutates state with no token/origin check; `gorilla/csrf` not wired
- PHP (raw): `session_start()` + state change with no token verification

Cookie flags that defeat SameSite-based protection:
- `SameSite=None` (or default — historically treated as `None`) without `Secure` and no token
- `SameSite=Lax` combined with a GET-based state change (e.g. `app.get('/delete/:id', ...)`)
- Cookie set without any `SameSite` attribute on legacy cookie paths

Token handling that defeats the defense:
- Token read from / validated only on the client (`if (localStorage.csrf === form.csrf)`)
- Token stored in a `SameSite=None; Secure` cookie **and** validated only via `SameSite` (no server-side value check) — relies on Lax+POST only
- Double-submit token not bound to a session/signed cookie (so any token validates any request)
- Token reused indefinitely, never rotated; mismatch logged but request still processed

Origin/Referer checks absent or weak:
- No `req.headers.origin` / `req.headers.referer` comparison on mutating handlers
- Allow-list built with `String.includes` / `endsWith` (e.g. `.includes('example.com')` → bypassable via `example.com.evil.tld`)
- CORS: `Access-Control-Allow-Origin` reflects `req.headers.origin` AND `Access-Control-Allow-Credentials: true`

## False positives
- The API authenticates exclusively via `Authorization: Bearer` header (or other non-cookie, non-ambient credential). Browsers do not auto-attach bearer tokens cross-origin, so there is no ambient credential to forge — CSRF does not apply. (Confirm the token is never also accepted from a cookie.)
- All session cookies are `SameSite=Strict` (or `Lax` with only POST-based, non-idempotent state changes and no GET mutations). This is a meaningful mitigation; downgrade severity rather than dismiss. Note `Lax` is breached by top-level GET navigations and was historically bypassable in some browsers within 2 minutes of cookie set.
- The endpoint requires a re-authentication / step-up factor (current password, MFA code) for the state change — an out-of-band secret the attacker cannot forge.
- The request requires a custom header (e.g. `X-Requested-With`, `X-API-Key`) that cannot be sent cross-site without a preflight, AND the app rejects requests lacking it. Simple forms cannot set custom headers, so this is a partial defense (relies on CORS preflight enforcement).
- The action is idempotent and read-only (true GET) — no state change, no CSRF relevance.

## Attack scenario
1. The victim is logged in to `bank.example.com`; their session cookie is `SameSite=None` (or unset) and the `/transfer` endpoint checks no CSRF token.
2. The attacker hosts a page at `evil.tld` containing:
   ```html
   <form action="https://bank.example.com/transfer" method="POST">
     <input type="hidden" name="to" value="attacker">
     <input type="hidden" name="amount" value="10000">
   </form>
   <script>document.forms[0].submit()</script>
   ```
3. The victim, while authenticated, visits `evil.tld` (phishing link, malicious ad, compromised site).
4. The browser auto-attaches the victim's session cookie to the cross-site POST; the server executes the transfer in the victim's authenticated context.
5. The attacker has moved funds / changed the recovery email / deleted the account without ever possessing the victim's password or cookie value.

## Impact
- **Confidentiality**: limited direct disclosure, but account takeover exposes all victim data.
- **Integrity**: full — the attacker can perform any action the victim is authorized for (fund transfers, privilege changes, password/email reset, data deletion).
- **Availability**: destruction or corruption of victim-owned resources.
- Severity scales with the victim's role; an admin victim enables full application compromise, mass account manipulation, or data exfiltration via chained actions.

## Remediation
Prefer a server-enforced synchronizer token or SameSite cookies; never rely on client-side checks:
```ts
// VULNERABLE — ambient cookie auth, no CSRF defense
app.post('/transfer', (req, res) => transfer(req.body));

// SAFE — double-submit token bound to a signed SameSite=Strict cookie + Origin check
import { doubleCsrf } from 'csrf-csrf';
const { doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: 'csrf',
  cookieOptions: { sameSite: 'strict', secure: true, httpOnly: true, signed: true },
});
app.use(doubleCsrfProtection);
app.post('/transfer', (req, res) => {
  const origin = req.headers.origin || '';
  if (!/^https:\/\/(app\.)?example\.com$/.test(origin)) return res.sendStatus(403);
  transfer(req.body);
});
```
Set session cookies `Secure; HttpOnly; SameSite=Lax` (or `Strict` where UX permits), validate `Origin`/`Referer` with a strict anchored regex, and avoid GET for any state change. Defense-in-depth: require a custom request header (`X-Requested-With`) and a strict Content Security Policy with `frame-ancestors 'self'` to block simple-form / framed CSRF and clickjacking-aided variants.

## References
- OWASP ASVS V3.x — Session management and session tokens
- OWASP WSTG-SESS-04 — Testing for Session Fixation; WSTG-INPV-12 — Testing for CSRF
- OWASP Cheat Sheet: Cross-Site Request Forgery Prevention
