---
id: P112
name: OAuthTokenHandling
area: V10 OAuth and OIDC
refs: ASVS V3.x / WSTG-SESS / CS: OAuth 2.0 Protocol, Session Management
---

# P112 — OAuthTokenHandling

## Overview
OAuth 2.0 and OIDC delegate authentication to an authorization server and issue bearer tokens that the client presents to resource servers. A bearer token is a bearer of fact — anyone who holds it can use it until it expires — so the entire security posture hinges on **how tokens are stored, transported, rotated, and revoked**. The recurring root causes are: storing access or refresh tokens in browser-readable locations (`localStorage`, `sessionStorage`, plain cookies) where XSS can exfiltrate them; long-lived access tokens without refresh-token rotation; missing or unenforced token revocation; and overly broad scopes. Sender-constraining (DPoP/mTLS) is the strongest defense but is rarely adopted, leaving a stolen token fully usable for its lifetime.

## What to check
- Where are tokens persisted on the client? `localStorage`/`sessionStorage` (XSS-readable), `document.cookie` without `HttpOnly`+`Secure`+`SameSite`, or in-memory / `HttpOnly` cookie (preferred)?
- Are access tokens short-lived (minutes, e.g. 5-15 min) and paired with a refresh token, rather than a single long-lived bearer?
- Is **refresh-token rotation** implemented (a new refresh token per use) with **reuse detection** (the old refresh token is revoked and the family invalidated when replayed)?
- Are refresh tokens stored server-side with state (hashed) or are they stateless JWTs without revocation capability?
- Is there a working **revocation endpoint** (`/oauth/revoke`, RFC 7009) and is it called on logout / password change / breach?
- Are tokens transmitted **only over HTTPS** as `Authorization: Bearer <token>`? Any token in a URL query string, redirect parameter, or referrer-leaking page?
- Are scopes requested with **least privilege** (`profile email`), never `openid offline_access *` blanket-scoped? Are issued scopes validated server-side on every request?
- Are tokens **sender-constrained** (DPoP proof, mTLS `tls-client-auth`, token binding) or plain bearer?
- Does the client validate `iss`, `aud`, `exp`, `nbf`, `alg`/signature on received tokens; are clock-skew leeways minimal?
- Are token lifetimes / scope / client secrets configurable and overridden to safe defaults in cloud identity providers (Cognito, Auth0, Azure AD, Okta)?
- Are **client credentials** (machine-to-machine) using a secret or `private_key_jwt`/mTLS, never the implicit flow, and never hardcoded?

## Static signals
Token storage in browser-insecure locations:
- JS: `localStorage.setItem('access_token', ...)`, `sessionStorage.setItem('token', ...)`, `document.cookie = 'token=' + at` (no `HttpOnly`), `window.__TOKEN__ = at`
- Framework: Pinia/Redux state populated from `localStorage` at boot, `axios.defaults.headers.Authorization` set from `localStorage`
- React/Vue: `localStorage.getItem('accessToken')` inside a hook/component

Token-in-URL transport (referrer/log leak):
- `fetch(\`/api?access_token=${at}\`)`, `window.location = '/x?token=' + at`, redirect_uri carrying `#access_token=` (implicit flow)

Missing rotation / reuse detection on refresh:
- Node: `jwt.sign(user, secret, { expiresIn: '30d' })` (one long-lived token, no refresh)
- Token-refresh handler that issues a new access token **without rotating** the refresh token, or does not revoke the prior one
- Python/Java refresh endpoints returning the same refresh token repeatedly (no `rotateRefreshToken: true`)

Hardcoded secrets / insecure client config:
- `clientSecret: '...'` in source, `grant_type: 'password'` (ROPC, deprecated/insecure), `response_type: 'token'` (implicit)
- Passport/oidc/client libs configured with `session: false` + tokens in localStorage, or `store: new MemoryStore()` in production

Cloud IdP misconfig (Terraform/CloudFormation/SDK):
- AWS Cognito: `AccessTokenValidity: 24` (hours — far too long), `ExplicitAuthFlow: ALLOW_USER_PASSWORD_AUTH`, missing token revocation on logout
- Auth0: `{ tokenEndpointAuthMethod: 'none' }` for confidential client, refresh-token rotation disabled
- Azure AD: app manifest `"accessTokenAcceptedVersion": 1`, `"allowPublicClient": true`, long `refreshTokensValidFrom`

Bearer-only (no sender constraint):
- Resource server validates JWT signature but never checks `cnf.jkt` (DPoP) or client cert — plain bearer accepted

## False positives
- The token stored in `localStorage` is a non-sensitive UI token (e.g. a theme/locale preference), not an OAuth access/ID/refresh token.
- Public SPA client with no backend uses in-memory access token + BFF/`HttpOnly`-cookie refresh handled by a server-side proxy (legitimate architecture); confirm the refresh path is still sender-constrained or short-lived.
- `grant_type: 'password'` in a legacy first-party mobile app being migrated; flag for upgrade but confirm no third-party use.
- Long lifetime is an intentional server-to-server client-credentials token protected by mTLS and IP allow-listing — verify the constraint is actually enforced.
- `document.cookie` write that sets a `__Host-` prefixed, `HttpOnly; Secure; SameSite=Strict` cookie containing only a session id, not the raw OAuth token.

## Attack scenario
1. A reflected/stored XSS bug (see P38/P39) executes in the victim's browser on `app.example.com`.
2. The SPA keeps the access token in `localStorage` (`localStorage.getItem('accessToken')`); the script reads it with `localStorage.getItem('accessToken')` and POSTs it to `evil.example.com`.
3. Because the access token is a plain bearer valid for 8 hours, the attacker replays it against `/api/me` and `/api/transfer` from any IP — no sender constraint, no revocation channel used by the victim.
4. The refresh token is also in `localStorage` and never rotates; the attacker keeps minting fresh access tokens after logout, sustaining access for weeks (until rotation/revocation finally fires, if ever).

## Impact
- **Confidentiality**: full read of the victim's protected resources via the API; long-term account access while tokens remain valid.
- **Integrity**: the attacker can perform any action the token's scopes permit (transfer funds, change email/password, export data).
- **Availability**: refresh-token reuse without detection can let an attacker lock out or shadow the legitimate user.
- Severity scales with scope (`openid profile` vs. `payments:write`), access-token lifetime, and whether sender-constraining/revocation is in place — an 8-hour `*`-scoped bearer with no rotation is effectively account takeover.

## Remediation
Store tokens in a `HttpOnly`-cookie (or behind a BFF); rotate refresh tokens with reuse detection; prefer sender-constrained tokens:
```ts
// VULNERABLE — long-lived token in localStorage, plain bearer, no refresh rotation
const at = jwt.sign({ sub: uid, scope: '*' }, SECRET, { expiresIn: '8h' });
res.json({ access_token: at });
// client.js
localStorage.setItem('access_token', at);
axios.defaults.headers.Authorization = `Bearer ${at}`;
```
```ts
// SAFE — short access token in HttpOnly cookie + rotating refresh token, DPoP-bound
const access  = jwt.sign({ sub: uid, scope: 'profile:read' }, SECRET, { expiresIn: '10m' });
const refresh = await issueRefreshToken(uid, { rotate: true, reuseDetection: true });
res.cookie('at', access,  { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 10*60_000 });
res.cookie('rt', refresh, { httpOnly: true, secure: true, sameSite: 'strict', path: '/oauth/refresh' });
// validate DPoP proof (cnf.jkt) on every protected request; revoke on logout
```
Configure the IdP to shortest practical token lifetimes, least-privilege scopes, and enforce revocation on logout/password change — defense-in-depth even when the primary storage is sound.

## References
- OWASP ASVS V3.x — Authentication and session management requirements (OAuth/OIDC token handling, session timeout, revocation)
- OWASP WSTG-SESS — Testing for Session Management (token lifetime, session fixation, logout)
- OWASP Cheat Sheets: OAuth 2.0 Protocol, Session Management, JSON Web Token for Java
