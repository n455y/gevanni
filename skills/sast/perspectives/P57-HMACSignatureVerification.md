---
id: P57
name: HMACSignatureVerification
refs: ASVS V6.2.x / WSTG-CRYP-04 / CS: Cryptographic Storage, JSON Web Token
requires: [backend]
---

# P57 — HMACSignatureVerification

## Overview
HMAC signature verification protects the integrity and authenticity of messages, webhooks, SAML assertions, and JWT/JWS tokens by recomputing a MAC over the payload with a shared secret and comparing it to the received signature. It fails when a receiver skips verification entirely, performs a non-constant-time comparison (leaking the secret or valid prefix via timing), accepts an attacker-influenced algorithm (`alg:none`, RS256↔HS256 key confusion), or canonicalizes whitespace/newlines before signing without doing the same on verify (normalization bug). The root cause is always the same: untrusted input is acted upon before its authenticity is proven with a pinned algorithm and the correct key. Webhook receivers are the most common offender because the secret lives server-side and the verification step is easy to forget or implement partially.

## What to check
- Does the handler recompute the HMAC over the **exact raw bytes** of the received body (not `JSON.parse` then re-serialize, which reorders/normalizes and breaks the MAC)?
- Is the signature compared with a **constant-time** equality (`crypto.timingSafeEqual`, `hmac.compare_digest`, `MessageDigest.isEqual`, `hash_equals`, `subtle.ConstantTimeCompare`) rather than `===`, `==`, `.equals()`, or `memcmp`?
- For JWT/JWS, is the `alg` header **pinned to an allow-list** (e.g. `HS256` only, or `RS256` only) and is the key chosen by the verified algorithm — not by the untrusted `kid`/`alg` header?
- Is the algorithm explicitly set on both sign and verify sides, rejecting `none` and refusing symmetric verification of an asymmetric key (and vice versa)?
- Is there replay protection — a timestamp window check (`abs(t - now) < 300s`) plus a nonce/cache of seen signatures?
- Are the signed bytes canonicalized identically on both sides? If the sender strips trailing whitespace or sorts headers, the receiver must do the same before HMAC.
- Is the shared secret fetched from a secret manager / env var, never logged, and rotated — not hardcoded next to the comparison?
- Does SAML verify the XML signature over the canonicalized (`C14N`) bytes and reject **signature wrapping** (assertion signed but not the envelope, or signed response with attacker-inserted assertion)?

## Static signals
Timing-unsafe comparison of a MAC/signature:
- `crypto.createHmac('sha256', SECRET).update(body).digest() === sig`
- Node: `req.headers['x-signature'] === hmac`, `Buffer.compare(...) === 0` (ok) but `buf.equals(sig)` without length guard
- Python: `hashlib.sha256(...).hexdigest() == sig`, `hmac.new(key, msg).hexdigest() == sig` (use `hmac.compare_digest`)
- Java: `mac.doFinal().equals(...)`, `Arrays.equals`, or `new String(macBytes).equals(sig)`
- Go: `bytes.Equal(mac.Sum(nil), sig)` (use `hmac.Equal`)
- PHP: `hash_hmac('sha256', $body, $secret) === $_SERVER['HTTP_X_SIGNATURE']` (use `hash_equals`)
- Ruby: `OpenSSL::HMAC.hexdigest('sha256', key, body) == sig` (use `Rack::Utils.secure_compare` or `OpenSSL::fixed_length_secure_compare`)
- C#: `Encoding.UTF8.GetString(mac).Equals(sig)` (use `CryptographicOperations.FixedTimeEquals`)

Verification omitted or short-circuited:
- `const event = JSON.parse(req.body); ... /* no verify */`
- `if (sig.startsWith(prefix))` — prefix match, partial verification
- `try { jwt.decode(token) } catch {}` — `decode` does NOT verify; only `verify` does
- Python: `jwt.decode(token, options={'verify_signature': False})` or `jwt.decode(token, verify=False)`

Algorithm not pinned / key confusion:
- `jwt.verify(token, secretOrPublicKey)` where the key is chosen from the `kid` header or a single key object supporting both HS/RS
- `algorithm: 'HS256'` absent on verify (library default may accept `none`)
- PyJWT: `algorithms=[...]` omitted → `AlgorithmError`; explicitly listing `['none']`
- Java JJWT / Nimbus: verifying RS256 with the public key but the token presents `alg: HS256` signed with the public key as HMAC secret

Signed over normalized bytes:
- `const ev = JSON.parse(rawBody); const body = JSON.stringify(ev);` then HMAC over `body` (byte order/spacing differs)
- Allowing leading/trailing `\n`, `\r\n` normalization mismatch, or `+` vs `%20` before signing

SAML / XML signature wrapping:
- Verifying a signature on the `<Response>` but reading claims from an unsigned `<Assertion>`
- Using `xmldsig` without exclusive C14N, or trusting `Reference URI` to point at the attacker's element

## False positives
- The receiver pins a single algorithm, uses constant-time comparison over the raw body, checks a timestamp window and nonce, and the secret is not hardcoded — fully protected.
- The signature is verified by a mature library with `algorithms` explicitly set and the key sourced by algorithm, not by header (e.g. `jwt.verify(token, getKey, { algorithms: ['RS256'] })` with JWKS keyed by `kid` that is mapped, not blindly trusted).
- The payload is unsigned but integrity is provided by a transport-level guarantee (mTLS over a private network with mutually authenticated clients) AND the data never crosses a trust boundary.
- The comparison uses `bytes.Equal` / `===` on a value derived from a trusted internal call (no attacker influence on either operand) — still flag for defense-in-depth, but not exploitable.

## Attack scenario
1. Recon: attacker registers a webhook listener or sends a request to the target's `/webhook` endpoint and observes no `X-Signature` validation error when the header is omitted.
2. Forge: attacker POSTs a crafted payload (`{"event":"account.update","balance":999999}`) with no signature, or a signature over re-serialized bytes that the server happens to accept.
3. Algorithm confusion variant: attacker takes the server's RS256 public key (from JWKS), re-signs the forged JWT with `alg: HS256` using that public key as the HMAC secret; a verifier that picks HMAC when `alg` says so accepts it.
4. Timing variant: server uses `===`; attacker brute-forces the correct MAC byte-by-byte by measuring response time across thousands of requests (or recovers the shared secret if the MAC output is compared directly).
5. Replay variant: no timestamp/nonce check — attacker captures a prior valid signed request and replays it to repeat a payment or state change.
6. The forged/replayed event is processed as authentic: balance updated, order shipped, account email changed, or internal sync triggered.

## Impact
- **Integrity**: full — an attacker injects arbitrary authenticated messages, the highest-impact failure for a MAC primitive.
- **Confidentiality**: usually none directly, but secret extraction via timing attacks exposes the HMAC key, enabling ongoing forgery and decryption of any data protected by the same key.
- **Availability**: replay floods or crafted events can corrupt downstream state and trigger cascading failures.
- Severity scales with what the signed channel authorizes: webhook-driven payment/refund flows and SAML SSO assertions are critical; low-value status callbacks may be moderate. Timing leaks that recover the secret raise any rating by a level.

## Remediation
Pin the algorithm, sign over raw bytes, and compare constant-time:
```ts
// VULNERABLE — non-constant-time compare over parsed body, no alg/replay check
const event = JSON.parse(req.body);
const expected = crypto.createHmac('sha256', SECRET).update(req.body).digest('hex');
if (expected !== req.headers['x-signature']) return res.sendStatus(401);
handleEvent(event);

// SAFE — raw bytes, fixed-time compare, timestamp window, pinned digest
const raw = req.rawBody;                       // pre-parsed buffer, exact bytes
const ts   = Number(req.headers['x-timestamp']);
if (Math.abs(Date.now()/1000 - ts) > 300) return res.sendStatus(401);
const mac  = crypto.createHmac('sha256', SECRET).update(`${ts}.${raw}`).digest();
const sig  = Buffer.from(req.headers['x-signature'], 'hex');
if (sig.length !== mac.length || !crypto.timingSafeEqual(mac, sig)) return res.sendStatus(401);
const event = JSON.parse(raw.toString());
handleEvent(event);
```
For JWT, pass an explicit `algorithms` allow-list and source the key by the verified algorithm (not the token header); for SAML, validate the signature over canonicalized bytes and reject signature wrapping. As defense-in-depth, log verification failures, rate-limit the endpoint, and rotate the shared secret on a schedule.

## References
- OWASP ASVS V6.2.x — Cryptographic verification of integrity and signatures
- OWASP WSTG-CRYP-04 — Testing for weak SSL/TLS, cryptography, and key management (timing/replay)
- OWASP Cheat Sheets: Cryptographic Storage, JSON Web Token, SAML Security
- RFC 2104 (HMAC), RFC 7515 (JWS), RFC 8725 (JWT Best Current Practices)
