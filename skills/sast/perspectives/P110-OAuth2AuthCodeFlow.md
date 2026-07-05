---
id: P110
name: OAuth2AuthCodeFlow
refs: ASVS V2.x / WSTG-ATHN-09 / CS: OAuth 2.0 Protocol
requires: [backend]
---

# P110 — OAuth2AuthCodeFlow

## Overview
The OAuth 2.0 Authorization Code flow exchanges a short-lived `code` (returned via the browser redirect) for tokens at the token endpoint. Its security rests on four pillars that are routinely misimplemented: **PKCE** (so an intercepted code cannot be redeemed), the **`state`** parameter (anti-CSRF binding of the callback to the original request), **strict `redirect_uri` validation** (so codes are not leaked to attacker-controlled or open-redirect hosts), and the avoidance of the **implicit** (`response_type=token`) and **resource-owner password** grants, which expose tokens to the browser and leak credentials respectively. The root cause of nearly every OAuth account-takeover bug is one of: omitting PKCE on a public/SAGL client, accepting any `state`, performing prefix/substring matching on `redirect_uri`, or treating the authorization code as replayable and client-unbound.

## What to check
- Is **PKCE** (`code_challenge` / `code_challenge_method=S256`) enforced for every client, and *mandatory* for public (SPA, mobile) clients? Plain `S256` — never `plain`.
- Is the **`state`** parameter generated server-side as a high-entropy, CSRF-bound value (tied to the user session or a signed cookie) and validated on the callback *before* the token exchange? Reject callbacks with missing/`state` mismatch.
- Is **`redirect_uri`** validated with **exact scheme+host+path** string equality against the registered value (no scheme/authority wildcarding, no path-only matching, no open-redirect chaining through a `next` param)? For OIDC also check `iss` / `client_id` on the callback.
- Is the client **confidential** (stores a `client_secret` server-side) when it can be? SPAs must be treated as public and therefore must use PKCE with no static secret.
- Is the **authorization code single-use**, short-lived (~30-60s), bound to the client_id and to the `redirect_uri` used at the authorization request, and rejected on replay?
- Are **`response_type=token`/`id_token` (implicit)**, `response_type=password`, and `client_credentials` used for user login? They must not be — implicit leaks tokens to the browser history/Referer; ROPC leaks passwords.
- Does the token exchange (`/token`) happen **server-to-server** over a back channel, with TLS, and is the resulting `access_token`/`refresh_token` never embedded in the front-end URL or `localStorage` unbound to an HttpOnly cookie?
- Is the callback handler immune to **login CSRF / session fixation** — does it discard/rotate the pre-auth session and bind the new identity to the post-auth one?
- Are token responses sent with `Cache-Control: no-store` and is `redirect_uri` rejection logged?

## Static signals
Missing / weak PKCE:
- Node `passport-oauth2`: no `pkce: true` / no custom `state` store; `simple-oauth2`, `openid-client` configured without `response_type: 'code'` plus PKCE on a public client.
- Python `authlib` / `requests-oauthlib`: `OAuth2Session` without `code_challenge_*`; `Authlib` client lacking `code_challenge_method='S256'`.
- Java `spring-security-oauth2-client`: `ClientRegistration` with `client-authentication-method: none` (public) and no PKCE verifier generation (Spring enables PKCE by default for public clients since 5.3 — confirm it was not disabled).
- Go `golang.org/x/oauth2`: `oauth2.Config` used directly without `oauth2.GenerateVerifier()` / `AuthCodeURL(..., oauth2.SetAuthURLParam("code_challenge", ...))`.
- Ruby `omniauth-oauth2`: no `pkce` option; `option :pkce, false`.

Weak `redirect_uri` / `state`:
- `if (redirect_uri.startsWith(registeredUri))` — prefix match (VULNERABLE).
- `if (redirect_uri.includes(registeredUri))` / `redirect_uri.contains(host)` — substring (VULNERABLE).
- `new URL(redirect_uri).host === 'example.com'` while ignoring path — path-traversal/`/redirect` abuse.
- Hardcoded `state: 'static'`, empty `state`, or `state` echoed from the request (`state = req.query.state`).
- Authorization request built without `state`: `AuthCodeURL(url, oauth2.AccessTypeOnline)` only.
- Authlib/Flask: `@app.route('/callback')` calling `authorize_access_token()` with `OAUTH_BTN_STATE` not compared.

Code-reuse / binding:
- Token endpoint / callback that does `tokens = exchange(code)` without passing `redirect_uri` or `client_id` to bind the code.
- Storing the code in `localStorage`/URL and redeeming it client-side (implicit-like misuse of the code flow).
- Refresh tokens with no rotation, no binding, infinite lifetime.

Config / IaC:
- Auth server config (Keycloak/Dex/Authelia): `redirectUris: ['*']` or `['https://*.example.com/*']` wildcard.
- AWS Cognito / App Service auth: implicit flow enabled (`oauthFlows.implicit.authorizationUrl`) for a user-facing app; `AllowedOAuthFlows: ['implicit']` in CloudFormation.

## False positives
- A confidential server-side client (Spring/Next.js API route) exchanging the code server-to-server with a stored secret, PKCE optional but `state` still validated — the back channel compensates, though PKCE remains recommended.
- `redirect_uri` matching that *is* exact but appears permissive because many distinct URIs are registered — verify each is a distinct legitimate client, not a wildcard.
- An OIDC library (e.g. `openid-client`, `next-auth`, Spring) that auto-generates `state` and PKCE and validates them in its callback handler — confirm the defaults were not overridden.
- Resource-server endpoints that accept bearer tokens but perform no authorization code flow themselves (they are downstream, not the IdP client).

## Attack scenario
1. App omits PKCE and uses a weak/predictable or missing `state`. Attacker initiates the flow, captures their own `code`, and prepares a **login-CSRF / code-injection**: they start the flow as themselves, grab the `code`/`state`, and trick the victim's browser into completing *the attacker's* callback (`https://app/callback?code=ATTACKER_CODE&state=...`).
2. The victim's session now authenticates as the **attacker**, so any data the victim uploads (profile, payment, messages) lands in the attacker's account — and the attacker reads it later.
3. Alternatively, with **`redirect_uri` prefix-matching**, the attacker registers `https://app.example.com.evil.com/callback` or abuses an open redirect (`https://app.example.com/redirect?next=//evil/cb`). The authorization server redirects the victim's `code` to the attacker host.
4. With no PKCE, the attacker redeems the intercepted `code` at the token endpoint for the victim's `access_token`/`refresh_token` — full account takeover.

## Impact
- **Confidentiality**: full account takeover, exfiltration of victim data, third-party-API access via the stolen token.
- **Integrity**: attacker acts as the victim across every scope the token grants.
- **Availability**: token revocation / refresh-token abuse can lock the victim out.
- Severity scales with scopes and the privilege of the federated identity; a missing-PKCE + weak-redirect_uri bug on a high-privilege IdP is **Critical** (CVSS ~9). Login-CSRF alone is typically High.

## Remediation
Use PKCE on every client, exact `redirect_uri` matching, and a server-bound `state`:
```ts
// VULNERABLE — public client, no PKCE, prefix-match redirect_uri, state ignored
const url = oauth2.AuthCodeURL(''); // no state
// callback: if (req.query.redirect_uri.startsWith(registeredList)) exchange(req.query.code);

// SAFE — PKCE (S256), random state bound to session, exact redirect_uri
import crypto from 'node:crypto';
const verifier = crypto.randomBytes(32).toString('base64url');
const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
const state = crypto.randomBytes(16).toString('hex');
req.session.oauthState = state;
req.session.oauthVerifier = verifier;
const url = oauth2.AuthCodeURL(state, {
  access_type: 'online',
  code_challenge: challenge,
  code_challenge_method: 'S256',
});
// callback: assert req.query.state === req.session.oauthState (constant-time),
// exchange code with verifier AND the exact redirect_uri, single-use the code.
```
Defense-in-depth: disable implicit and ROPC flows at the authorization server, send tokens with `Cache-Control: no-store`/`Pragma: no-cache`, rotate refresh tokens on use, and require confidential clients wherever a server back channel exists.

## References
- OWASP ASVS V2.x — Authentication and federation verification requirements
- OWASP WSTG-ATHN-09 — Testing for OAuth 2.0 / OIDC weaknesses
- OWASP Cheat Sheet: OAuth 2.0 Protocol (PKCE, state, redirect_uri, grant-type selection)
