---
id: P14
name: JWTValidation
area: V6 Authentication
refs: ASVS V3.4.x, V3.5.x / WSTG-SESS-01, WSTG-ATHN-08 / CS: JSON Web Token Cheat Sheet
---

# P14 — JWT Validation

## Overview
JSON Web Tokens (JWTs) are self-contained, signed bearer tokens carrying claims such as `sub`, `exp`, `iss`, and `aud`. Because the server trusts the token's content based solely on its signature, any flaw in validation — accepting `alg:none`, trusting an attacker-controlled `alg` to select the verification key, skipping signature/expiry/issuer/audience checks, or signing with a weak or leaked secret — collapses authentication entirely. The root causes are almost always: omission of an explicit `algorithms` allow-list (enabling algorithm-confusion and `none` bypass), use of `decode`/unverified parse instead of `verify`, or a symmetric secret too short to resist offline brute force.

## What to check
- Is an **explicit allow-list of expected algorithms** passed to verification (e.g. `algorithms: ['RS256']`)? If omitted, `none` / RS256↔HS256 confusion is often possible.
- Is `verify()` / library-equivalent used — never `decode()`, `unverify`, or manual base64 split — so the signature is actually checked?
- Are the following claims validated, not just parsed: `exp` (expiry, **not** ignored), `nbf`, `iat`, `iss` (issuer), `aud` (audience bound to this service)?
- Is the **correct key** used per algorithm? An RSA public key must never be accepted where the library expects an HMAC secret — the classic HS256-confusion attack.
- Is the HMAC secret strong (≥32 random bytes, ideally ≥128 bits) and not hardcoded, committed, logged, or rotated periodically?
- For asymmetric keys, is the public key fetched from a trusted source (JWKS with `kid` validation, pinned URL) and is the `kid` header screened for path/injection abuse?
- Are tokens issued with short lifetimes, paired with a refresh-token flow and a server-side revocation list for logout?
- Is the JWT stored in an `HttpOnly`, `Secure`, `SameSite` cookie rather than `localStorage`, to reduce XSS-exposure risk?

## Static signals
Verification without algorithm pinning / with bypasses:
- `jwt.verify(token, secret)` with **no** `algorithms` option (Node `jsonwebtoken` — historically accepts `none`)
- `jwt.verify(token, key, { algorithms: null })`, `{ algorithm: ... }` typo, or `algorithms: ['none']`
- `jwt.verify(token, key, { ignoreExpiration: true })`, `ignoreNotBefore: true`
- `jwt.decode(token)` used to read claims (no signature check); `jwt.decode(token, { complete: true })`
- Python `PyJWT`: `jwt.decode(token, key, options={'verify_signature': False})`, `{'verify_exp': False}`, or `algorithms` omitted
- `jose`/`python-jose`: `jwt.decode(token, key)` without `algorithms=[...]`
- Java `jjwt`: `Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token)` missing `.setSigningKeyResolver(...)` or algorithm pin
- Go `golang-jwt`: `jwt.Parse(token, keyFunc)` — keyFunc derives key without asserting `Method`/alg

Wrong-key / key-mismatch patterns (RS↔HS confusion):
- `jwt.verify(token, publicKey, { algorithms: ['HS256'] })` — public key fed as HMAC secret
- A single key/secret that is hardcoded: `const SECRET = 'supersecret'`, `SECRET_KEY = 'changeme'`, `JWT_SECRET = "secret"`

Weak / leaked secrets:
- `Math.random()` / `Date.now()` used to derive a secret; secret < 16 bytes; secret read from `process.env` that defaults to a short literal
- Secret logged: `console.log('using key', secret)`; secret echoed in error responses

Token storage / handling:
- `localStorage.setItem('token', jwt)` (XSS-readable) rather than an HttpOnly cookie

## False positives
- `algorithms` is explicitly set to the one expected algorithm (e.g. `['RS256']`) **and** the key is loaded from a managed store with rotation — this is the secure pattern, not a finding.
- `jwt.decode()` is used purely for client-side display of non-security claims (e.g. showing a username) while an authoritative server-side `verify()` gates every privileged action.
- Short-lived access tokens (≤15 min) with a refresh-token rotation and revocation list compensate for some risk; still verify, but severity is reduced.
- Stateless JWTs intentionally omit server-side revocation where the token lifetime is very short and the threat model accepts it — confirm expiry is short before closing.
- The token is an opaque session ID mislabeled "JWT" in comments; verify the actual format before flagging.

## Attack scenario
1. Attacker registers or captures a legitimate token (or just takes a public RSA key from the service's JWKS endpoint).
2. **`alg:none` bypass**: attacker rewrites the header `{"alg":"none","typ":"JWT"}`, drops the signature, and sets elevated claims (e.g. `"role":"admin"`). A verifier that does not pin `algorithms` and falls back to `none` accepts it.
3. **Algorithm confusion (RS256→HS256)**: attacker signs a forged token with HMAC using the service's **public** RSA key as the secret and header `{"alg":"HS256"}`. A verifier that picks the verification key by the token's own `alg` will HMAC-verify against the public key and trust the forged payload.
4. **Weak-secret cracking**: attacker grabs a sample HS256 token and runs `hashcat -m 16500` offline against a weak secret like `secret123`, recovering the key and minting arbitrary tokens.
5. With an admin token, the attacker accesses every account, exfiltrates data, and pivots — the breach is often undetected because the forged tokens pass all signature checks.

## Impact
- **Confidentiality**: total — forged tokens impersonate any user, including admins; full data exposure.
- **Integrity**: arbitrary actions (fund transfers, privilege grants, config changes) performed as the victim or superuser.
- **Availability**: mass account lockout, destructive admin actions, or forced logouts via crafted `exp` values.
- Severity is **Critical** whenever the secret is weak/leaked or `alg` is not pinned; downgrade to High only when impact is contained by secondary controls (mTLS, IP allow-listing, very short TTL).

## Remediation
Pin the algorithm, verify every claim, and use a strong asymmetric key:
```ts
// VULNERABLE — no algorithm pin, expiry ignored, weak secret, decode used for claims
const payload = jwt.decode(token);
jwt.verify(token, 'supersecret', { ignoreExpiration: true });

// SAFE — explicit algorithm, all claims checked, asymmetric key
const payload = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],   // reject none and HS256 confusion
  issuer:   'https://auth.example.com',
  audience: 'api.example.com',
  clockTolerance: 30,
});
```
Store tokens in `HttpOnly; Secure; SameSite=Strict` cookies, keep access-token TTL short (≤15 min) with a rotating refresh token and a revocation list, and load signing keys from a managed secret store with rotation. Defense-in-depth: monitor for `alg:none` tokens at the edge (WAF rule) and reject them before they reach the verifier.

## References
- OWASP ASVS V3.4.x (token-based session), V3.5.x (token revocation & expiration)
- OWASP WSTG-SESS-01 (Session Management), WSTG-ATHN-08 (Testing for Weak Authentication on Tokens/JWTs)
- OWASP Cheat Sheet: JSON Web Token
