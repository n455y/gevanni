---
id: P123
name: SelfContainedTokens
refs: ASVS V9.x / WSTG-SESS / CS: JSON Web Token, OAuth 2.0 Protocol
---

# P123 — SelfContainedTokens

## Preconditions

The code processes self-contained tokens.


## Overview
Self-contained tokens (JWT/JWS, PASETO) carry their own claims and signature so a stateless server can authenticate without a session lookup. That autonomy is also the risk: every verification step — algorithm, signature, `iss`, `aud`, `exp`, `nbf` — is the application's sole responsibility, and the token format exposes attacker-controllable fields (the JOSE header's `alg`, `kid`, `jwk`, `jku`, `x5u`) that libraries have historically mishandled. The root causes are (1) accepting a token signed with an algorithm the issuer never intended (algorithm confusion / `alg=none`), (2) resolving header-controlled keys against the filesystem or a remote URL (key injection / path traversal), and (3) skipping claim validation so a stolen, replayed, or cross-service token is honored. Because the bearer *is* the credential, any signature bypass or token leak is a direct authentication bypass.

## What to check
- Is the expected `alg` pinned to an explicit allow-list (e.g. `RS256`) and enforced on verify? Flag any code that takes `alg` from the token header, falls back to `none`, or passes the public key as a symmetric secret.
- Is the `kid` header treated as untrusted input? Flag `kid` used directly in a file/database lookup (`fs.readFileSync('/keys/'+kid)`, SQL string concat) — path traversal (`../../dev/null`, `....//`) and SQLi via `kid` are classic.
- Are `jku`/`jwk`/`x5u`/`x5c` headers honored to fetch keys remotely or embed them inline? Any token that supplies its own verification key is a forgery primitive unless pinned to a trusted allow-list of URLs/keys.
- Is the signature actually verified before claims are read? Flag code that base64-decodes the payload (`jwt.decode`) and trusts it, or calls `verify` inside a `try/catch` that swallows the error.
- Are all binding claims validated: `iss` (expected issuer), `aud` (expected audience, server itself), `exp` (clock skew bounded), `nbf`, `iat`? Flag absent `aud` checks and large clock-tolerance windows.
- Is the signing key rotated on a schedule, and is the published JWKS fetched with caching/TTL (not on every request) and pinned to HTTPS endpoints owned by the issuer? Flag key-set fetches over HTTP, from a token-supplied URL, or without cache-flush on rotation.
- Are tokens transmitted in `Authorization: Bearer` headers (not URL query strings) so they do not leak into access logs, browser history, `Referer`, or proxy captures?
- For stateless sessions, is there replay protection (short `exp`, `jti` denylist/nonce, DPoP/mTLS binding) for high-value operations?
- Are PASETO libraries configured with the correct purpose (`local` vs `public`) and a non-default/filler key? `local` tokens require a symmetric key; misusing a public key as the shared secret breaks confidentiality.

## Static signals
Trust-without-verify (any language):
- JS/TS: `jwt.decode(token)` then read `.role`/`.sub`; `jwt.verify(token, secret)` where `secret` came from `publicKey` (RS256↔HS256 confusion).
- `algorithms` option omitted: `jwt.verify(token, key)` with no `{ algorithms: ['RS256'] }`.
- Python: `jwt.decode(token, options={'verify_signature': False})`, `jwt.decode(token, key, algorithms=None)`, PyJWT <2.4 known-confusable.
- Java: `Jwts.parser().setSigningKey(...)` with no `.setSigningKeyResolver` restricting alg/kid; `io.jsonwebtoken` <0.10 defaulting to asymmetric-as-symmetric.

Header-controlled key resolution:
- `fs.readFileSync(path.join(keyDir, header.kid))`, `fs.readFile('./keys/'+kid)`, `require('fs').readFileSync(kid)`
- `jwksClient`/`getKey` invoked with `header.jku` or token-supplied URL; `axios.get(token.header.jku)`.
- Go: `jwt.ParseWithClaims(...)` without a `Keyfunc` that validates `kid` against a known set and rejects `alg`.

Claim validation gaps:
- `jwt.verify(token, key)` with no `audience`/`issuer`/`clockTimestamp` options.
- `ignoreExpiration: true`, `clockTolerance: 300`+ seconds, `{ verify_exp: false }`.
- `jwt.verify(token, key, { algorithms: ['HS256','RS256','none'] })` — `none` in allow-list.

Token transport / logging:
- Tokens placed in URL: `?token=`, `?access_token=`, `window.location = '/x?jwt=' + token`.
- Tokens logged: `console.log(token)`, `logger.info('auth ' + token)`, Pino/Morgan without redaction.
- Cookie storage without `Secure`/`HttpOnly`/`SameSite`, or session tokens in `localStorage` (XSS-exposed).

## False positives
- The library pins `alg`, fetches JWKS only from a hard-coded HTTPS issuer URL, validates `iss`/`aud`/`exp`, and uses a vetted `Keyfunc` — this is the correct pattern, not a finding.
- `jwt.decode` used purely for debugging/logging the *payload shape* on the server side, while a separate `verify` call guards the actual decision.
- Asymmetric keys stored alongside the app for signing are *not* server secrets; their disclosure only matters if the verifying side is symmetric-only (then it is a real finding).
- PASETO `v4.public` with a properly generated Ed25519 key and purpose-checked parser — purpose/key-type enforcement is built in.
- Long-lived opaque reference tokens issued by an auth server and introspected per-request are not self-contained tokens (this perspective does not apply — see session/introspection perspectives).

## Attack scenario
1. Attacker registers an account and observes their own RS256 JWT plus the well-known JWKS URL of the target's issuer (no attack yet — just reconnaissance).
2. **Algorithm confusion variant:** the target's verifier uses `jwt.verify(token, publicKey)` with no `algorithms` allow-list. The library defaults to HS256 and HMACs with the *public RSA key* (which is non-secret). The attacker forges a token with `alg: HS256`, `sub: admin`, signs it with the leaked public key, and authenticates as the admin.
3. **`kid` path-traversal variant:** verifier resolves `fs.readFileSync('/keys/' + kid)`. Attacker sets `kid: "../../../../dev/null"`, `alg: HS256`; the empty file is the HMAC key for an empty/`none`-style signature, yielding a forged admin token.
4. **`jku`/`jwk` injection variant:** verifier fetches the verification key from `header.jku`. Attacker hosts their own JWKS at `https://evil/.well-known/jwks.json`, sets `kid` to point at their key, signs the token with their own private key, and the server trusts it because it trusts the token-supplied URL.
5. The forged or stolen token is sent as `Authorization: Bearer …`; the stateless API performs the privileged action with no server-side session to invalidate.

## Impact
- **Confidentiality**: full account takeover; forged tokens bypass MFA since the token is the authenticated credential.
- **Integrity**: attacker-issued claims (roles, scopes, `sub`) are honored — privilege escalation and fraudulent transactions.
- **Availability**: leaked short-`exp` tokens enable sustained automated abuse; in key-set poisoning, a poisoned JWKS can DoS auth for every consumer.
- Severity is **Critical** whenever signature verification is bypassable or an admin-claim forgery is accepted; **High** for token leakage via URL/logs; scales with claim flexibility and token lifetime.

## Remediation
Pin the algorithm, validate all claims, and never resolve keys from token-controlled input:
```ts
// VULNERABLE — alg taken from token; publicKey usable as HMAC secret; no claim checks
const claims = jwt.verify(token, publicKey);            // alg confusion (HS256 w/ RSA pubkey)
const claims = jwt.decode(token);                       // signature not checked at all

// SAFE — pinned alg, expected issuer/audience, bounded skew, JWKS from trusted URL only
const { header, payload } = jwt.verify(token, getIssuerKey, {
  algorithms: ['RS256'],                                // explicit allow-list, never 'none'
  issuer: 'https://auth.example.com',
  audience: 'api.example.com',
  clockTolerance: 30,                                  // seconds, not minutes
});
// getIssuerKey: resolve by header.kid ONLY against a cached JWKS fetched over HTTPS
// from the hard-coded issuer URL; reject if kid is unknown or header.jku/jwk is present.
```
Defense-in-depth: keep tokens short-lived, transmit only via `Authorization` headers over TLS with log redaction, rotate signing keys with overlapping grace periods, and bind high-value operations with DPoP/mTLS or a server-side `jti` replay cache.

## References
- OWASP ASVS V9.x — Communications and session/token security controls
- OWASP WSTG-SESS — Testing for Session Management and token weaknesses
- OWASP Cheat Sheets: JSON Web Token, OAuth 2.0 Protocol
