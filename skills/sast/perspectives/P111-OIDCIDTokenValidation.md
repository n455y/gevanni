---
id: P111
name: OIDCIDTokenValidation
refs: ASVS V2.x / WSTG-ATHN-09 / CS: OAuth 2.0 Protocol, JSON Web Token
requires: [backend]
---

# P111 — OIDCIDTokenValidation

## Overview
OpenID Connect (OIDC) authentication terminates in the **ID Token** — a signed JWT asserting the end-user's identity back to the client (Relying Party). Unlike an opaque session cookie the RP validates server-side, the ID Token is verified *locally* by the client using keys and parameters it must fetch and pin itself. Any skipped or incorrect check — signature, `iss`, `aud`, `exp`, `nbf`, `nonce`, algorithm, or the `at_hash`/`c_hash` binding — is an authentication-bypass primitive: an attacker who can mint or replay a token authenticates as an arbitrary user without touching a password. The root cause is almost always "I decoded the JWT but didn't *verify* it," trusting an attacker-controllable `alg` header, hardcoding `verify=false`, or accepting the wrong tenant's token.

## What to check
- Is the ID Token verified with a **signature check**, or merely base64-decoded (`jwt.decode` vs `jwt.verify`, `jsonwebtoken.verify` with no secret/key, PyJWT `decode(..., options={"verify_signature": False})`)?
- Is the signing **algorithm pinned** to the expected value (e.g. `RS256`), or does the verifier accept any `alg` from the token header — enabling the `alg:none` and algorithm-confusion (HS256-with-RSA-public-key) attacks?
- Are `iss`, `aud` (and multi-audience / `azp` when relevant), `exp`, `nbf`, and `iat` all validated against the client's own configured values and a server clock?
- Is the `nonce` sent in the authentication request stored server-side (or in an HMAC-bound cookie) and **compared** to the `nonce` claim in the returned ID Token? Is it single-use (consumed on success)?
- Are keys fetched from the discovered `jwks_uri` (OIDC discovery `.well-known/openid-configuration`) with **key rotation / cache refresh**, and is the key ID (`kid`) matched against the token header rather than a hardcoded stale key?
- Does the RP accept ID Tokens from the **authorization code flow** without validating `c_hash`, or implicit/hybrid tokens without `at_hash` (mix-up / token-injection)?
- Are validation failures (unknown user, wrong issuer, expired) reported with **identical generic messages and timing**, or do differential responses leak which identifier exists?
- Is the token replay-protected (short `exp`, one-time `nonce`, replay cache for `jti` where applicable)?
- Multi-tenant: is the token bound to the correct tenant/issuer and rejected if minted for a different one the same library also accepts?

## Static signals
Verification omitted or weakened:
- Node: `jwt.decode(token)` used as if verified; `jwt.verify(token, key)` with no `algorithms` option; `algorithms: ['none']`; `verify(token, secret)` where `secret` is the IdP RSA public key (HS256 confusion).
- Python: `jwt.decode(token, options={"verify_signature": False})`, `verify=False`, `verify_exp=False`; decoding with `PyJWT` without passing `audience=`/`issuer=`; `jwt` calls lacking `algorithms=[...]`.
- Java: `Jwts.parser().parse(token)` (no `setSigningKey`/`verifyWith`), `parseClaimsJws` without `requireIssuer`/`requireAudience`; Nimbus OIDC `IDTokenValidator` with `null` issuer or audience check disabled.
- Go: `jwt.Parse` without a `Keyfunc` that pins the alg, or returning the key for `alg="none"`; `UnverifiedClaims` parse used for auth decisions.
- PHP: `firebase/php-jwt` `JWT::decode($jwt, $keys)` without `$allowed_algs`, or an empty `[]` allowed-algs list.
- Ruby: `JWT.decode(token, key, false)` (third arg `false` disables verification); missing `algorithm:`.

Nonce / binding gaps:
- Auth request sends `nonce` but the callback never reads `id_token['nonce']`, or compares with `==` against a value still present in a URL/cookie the attacker controls.
- No `nonce` in the request at all for flows returning an ID Token via the front channel.
- `c_hash` / `at_hash` present in token but never recomputed and compared.

Discovery / JWKS:
- Hardcoded JWKS or `x5c` embedded in config with no rotation refetch.
- TLS to `jwks_uri` not pinned/validated; `insecure_skip_verify: true` on the discovery fetch.

Differential errors (user enumeration):
- "No account for that email" vs "Wrong password" style branching on OIDC `login_hint` / `email` flows; redirect-vs-error timing differences per identifier.

## False positives
- The library performs all checks when invoked correctly: Node `jsonwebtoken.verify(token, key, { algorithms: ['RS256'], issuer, audience, complete })`; PyJWT `jwt.decode(token, key, algorithms=['RS256'], audience=..., issuer=...)`; Nimbus `IDTokenValidator` configured with issuer, audience, and a `JwkDefinition`/`RemoteJWKSet`. Presence of a correctly-parameterized call is a pass, not a finding.
- `alg: none` accepted by design in a purely internal, mTLS- or HMAC-protected channel with no trust boundary (rare; document it).
- `jwt.decode` is used *only* to read claims **after** an independent `verify` call on the same token, not for access decisions.
- User enumeration does not apply if the IdP — not the RP — handles all login UI and error rendering, and the RP shows one uniform result.
- A library logs `kid`-not-found but still rejects the token; the warning is not a bypass.

## Attack scenario
1. Attacker observes the RP's OIDC config (`authorization_endpoint`, `jwks_uri`, `client_id`) and registers or controls any **other** account at the same IdP (or a confederate tenant the library also trusts).
2. They obtain a validly-signed ID Token — but issued for *their* user, *their* `aud`, or a different `iss`/tenant.
3. On the RP's callback (`/callback?code=...` or implicit `#id_token=...`) they substitute their crafted token, exploiting a missing `aud`/`iss`/`azp` check (token mix-up) or a missing `nonce` binding.
4. If `alg` is not pinned, the attacker forges a token with `alg:none` and an empty signature, or with `alg:HS256` signing the payload with the IdP's public key as the HMAC secret — bypassing the signature entirely. If `nonce` is unverified, they replay a token captured from another flow.
5. The RP sets a session for the `sub`/`email` claim in the forged token — the attacker is now authenticated as the victim (or as any user they name in the claim), completing account takeover without credentials.

## Impact
- **Confidentiality**: full account impersonation; the entire user identity, profile data, and any SSO-federated resource become accessible to the attacker.
- **Integrity**: attacker can perform any action the forged identity is authorized for; in SSO hubs, privilege escalation across every federated RP.
- **Availability**: replay / token-flooding against `jti`-less systems; tenant redirection attacks that lock users out.
- Severity is typically **Critical**: a single missing check converts an unauthenticated outsider into an arbitrary authenticated user. Blast radius scales with federation breadth (one RP accepting forged tokens may trust the same IdP for many services).

## Remediation
Verify the ID Token with every parameter pinned, in a library that rejects unknown algorithms by default:
```ts
// VULNERABLE — decode used as verify; alg, iss, aud, nonce all unchecked
const claims = jwt.decode(req.query.id_token);
req.session.user = claims.sub;

// SAFE — pin alg, verify signature, iss, aud, exp, nonce
const claims = jwt.verify(idToken, getKeyFromJwks, {
  algorithms: ['RS256'],          // never accept 'none' or client-controlled alg
  issuer: config.issuer,           // exact match to this RP's IdP/tenant
  audience: config.clientId,       // this RP only
  complete: false,
});
if (claims.nonce !== session.pendingNonce) throw new AuthError('nonce mismatch');
consumeNonce(session.pendingNonce); // single-use
```
Fetch keys from the OIDC discovery `jwks_uri` with rotation-aware caching, validate `exp`/`nbf`/`iat` against a synced clock, and recompute `at_hash`/`c_hash` when present. Render every login failure with one identical, constant-time generic message to avoid user enumeration via `login_hint`. Defense-in-depth: prefer the authorization-code flow with PKCE over implicit/hybrid, and never accept an ID Token from the front channel that you could have obtained via a back-channel token exchange.

## References
- ASVS V2.x
- WSTG-ATHN-09
- CS: OAuth 2.0 Protocol, JSON Web Token
