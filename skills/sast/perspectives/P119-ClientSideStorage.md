---
id: P119
name: ClientSideStorage
refs: ASVS V8.x / WSTG-CLNT / CS: HTML5 Web Storage, Session Management
---

# P119 — ClientSideStorage

## Preconditions

The code stores data in browser storage.


## Overview
Client-side storage abuse occurs when an application persists secrets — access tokens, refresh tokens, API keys, PII, or session identifiers — in browser-readable stores such as `localStorage`, `sessionStorage`, `IndexedDB`, or even URL fragments, **where any running script in the page origin can read them**. The root cause is conflating "needed by the UI" with "must be readable by JavaScript": once a token lives in `localStorage`, a single XSS — first-party or in any third-party script — can lift it cleanly. The durable, cross-tab nature of `localStorage` compounds the exposure: a stolen token often outlives the tab and sometimes the browser session. The safe pattern is to keep long-lived secrets in `HttpOnly` + `Secure` + `SameSite` cookies that JS cannot read, and to store only non-sensitive UI state client-side.

## What to check
- Where is the access token / refresh token / JWT persisted on the client? Confirm via DevTools Application > Local Storage / Session Storage / Cookies / IndexedDB, and via source review of the SPA login flow.
- Does the code call `localStorage.setItem` / `sessionStorage.setItem` / `indexedDB.add` with anything derived from authentication: `accessToken`, `idToken`, `refreshToken`, `token`, `jwt`, `Authorization`, a raw `Authorization: Bearer` value, decrypted PII, or a backend API key?
- Are long-lived server secrets (Stripe secret key, S3 credentials, service-account JSON, OAuth client secrets) shipped to the bundle and stored client-side? These belong server-side only.
- If cookies are used for the session, do they carry `HttpOnly`, `Secure`, and `SameSite=Lax|Strict`? A cookie missing `HttpOnly` is XSS-readable just like `localStorage`; missing `Secure` leaks over HTTP; missing `SameSite` widens CSRF surface.
- Is sensitive data placed in the URL — query string (`?token=...`) or hash fragment (`#access_token=...` in implicit-flow callbacks)? URLs are logged by proxies, referer headers, browser history, and server access logs.
- For tokens that *must* be exposed to JS (e.g., short-lived access tokens for API calls from the SPA), is the lifetime minimized and the refresh token kept in an `HttpOnly` cookie rather than alongside it?
- Are Bearer tokens sent to third-party origins (analytics, CDNs) where a script on those origins could read them from storage?
- Does the logout flow actually clear stored secrets (`localStorage.removeItem`, cookie expiry), or does the data persist across logout/reinstall?

## Static signals
Tokens written to web storage (any framework):
- `localStorage.setItem('token', accessToken)` / `localStorage.setItem('access_token', ...)`
- `sessionStorage.setItem('jwt', token)` / `localStorage['user'] = JSON.stringify({...token})`
- `Cookies.set('token', jwt)` (the `js-cookie` library writes JS-readable cookies — no `HttpOnly`)
- Framework idioms: Pinia/Redux persisting `auth` slice to `localStorage` (`createJSONStorage(() => localStorage)`), Angular `localStorageService.set('token')`, Vue `vue-persistedstate`, React `redux-persist` with `localStorage`.

Storing keys/PII client-side:
- `localStorage.setItem('apiKey', process.env.REACT_APP_STRIPE_SECRET)`
- IndexedDB: `db.transaction('secrets').objectStore('tokens').add({...})`
- `window.name = JSON.stringify(session)` (legacy stash, survives navigation)

Insecure cookies / token transport:
- `res.cookie('session', token)` without `{ httpOnly: true, secure: true, sameSite: 'lax' }`
- `document.cookie = 'token=' + jwt` (inherently non-HttpOnly)
- Implicit OAuth flow parsing `window.location.hash` → `#access_token=...` and storing it
- Query-string tokens: `history.pushState({}, '', '?token=' + token)`; `new URLSearchParams(location.search).get('token')`

## False positives
- Non-sensitive UI preference state in `localStorage` (theme, language, collapsed-sidebar flag, last-visited tab) — no credential value.
- Tokens stored in `HttpOnly` + `Secure` + `SameSite` cookies and never touched by JS — this is the recommended pattern, not a finding.
- A public API key / publishable key that is *designed* to be exposed client-side (e.g., Stripe `pk_live_`, Firebase `apiKey`, Google Maps browser key) — confirm the provider's threat model; these are safe to ship but must be domain-restricted.
- CSRF tokens are intentionally JS-readable (they must be attached to headers) — but they should be short-lived and not co-located with the session credential in a readable store.
- `sessionStorage` holding a value needed only for the current tab that contains no secret (e.g., a draft form id).

## Attack scenario
1. The SPA stores the access JWT in `localStorage` after login: `localStorage.setItem('accessToken', jwt)`.
2. The attacker finds (or buys) one XSS — a vulnerable dependency in a chat widget, a rich-text renderer, or a reflected-XSS bug — that executes in the application origin.
3. The injected script reads `localStorage.getItem('accessToken')` and POSTs it to `https://evil.example/collect`, all from the victim's browser with the victim's origin.
4. The attacker replays the Bearer token against the API — fully authenticated, bypassing MFA because the user already completed it. Because the token is long-lived and survives tab close, the window of abuse extends until the token expires or is revoked.
5. Variant for fragment tokens: a phishing page redirects to the real app's OAuth callback `...#access_token=...`; the value lands in the URL, is logged by a reverse proxy, and is also readable by any script before the SPA clears the fragment.

## Impact
- **Confidentiality**: full credential theft — access/refresh tokens, decrypted PII, API keys — readable by any XSS in the origin; URL-stored secrets leak via logs/referrer/history.
- **Integrity**: the stolen token authorizes actions as the victim (account takeover, data mutation, fund movement) without needing the password or a second factor.
- **Availability**: stolen long-lived refresh tokens can lock the legitimate user out (forced password reset / session revocation) or fund abuse-rate-limit exhaustion against the API.
- Severity scales with token lifetime and privilege: a `localStorage` admin refresh token turns any XSS into persistent full-admin compromise; a 5-minute access token with the refresh token in an `HttpOnly` cookie caps the blast radius to that token's TTL.

## Remediation
Keep long-lived secrets out of JS-readable storage; use `HttpOnly` + `Secure` + `SameSite` cookies for session credentials:
```ts
// VULNERABLE — token readable by any XSS, persists across tabs/sessions
function onLogin(res) {
  localStorage.setItem('accessToken', res.accessToken);
  localStorage.setItem('refreshToken', res.refreshToken);
}

// SAFE — session in an HttpOnly cookie the browser sends automatically;
// JS never sees the credential, so XSS cannot exfiltrate it directly.
app.post('/login', (req, res) => {
  const { accessToken, refreshToken } = issue(req.body);
  res.cookie('access_token', accessToken, {
    httpOnly: true, secure: true, sameSite: 'lax',
    maxAge: 5 * 60 * 1000,        // short-lived
    path: '/',
  });
  res.cookie('refresh_token', refreshToken, {
    httpOnly: true, secure: true, sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, path: '/auth',
  });
  res.json({ user: { id: res.userId } }); // no token in the body
});
```
If a short-lived access token genuinely must be JS-visible (e.g., for cross-origin API calls with credentials), keep *only* that token in memory (a JS variable), store the refresh token in an `HttpOnly` cookie, and never persist the access token to `localStorage`/`sessionStorage`. Add a strict Content-Security-Policy as defense-in-depth — it does not protect `localStorage` itself, but it bounds the XSS surface that could read it.

## References
- OWASP ASVS V8.x — Protection of data, in-transit and at-rest, including client-side data protection
- OWASP WSTG-CLNT — Client-side testing (HTML5 Web Storage, client-side storage analysis)
- OWASP Cheat Sheets: HTML5 Web Storage Security, Session Management, JSON Web Token for Java
