---
id: P56
name: KeyManagement
area: V11 Cryptography
refs: ASVS V6.2.x / WSTG-CRYP-04 / CS: Cryptographic Storage, Secrets Management
---

# P56 — KeyManagement

## Overview
Key-management failures occur when signing or encryption keys are treated as static configuration rather than as lifecycle-managed secrets: a single fixed key is hard-coded or read from disk and used forever, with no rotation, no multi-key (key-id) support, and no revocation path. The root cause is conflating "the algorithm is correct" with "the key is safe." Even strong cryptography becomes worthless once the key leaks, and without rotation or revocation a single compromise becomes permanent. A related and especially dangerous subclass is trusting attacker-influenced key identifiers — e.g. resolving a JWT `kid` header as a filesystem path — which collapses key selection into path traversal or arbitrary-key injection.

## What to check
- Is there **any** rotation mechanism for signing/encryption keys, or is one fixed key used indefinitely (measured in years)?
- Are multiple keys supported concurrently via a key-id (`kid`, `keyId`, key version) so that old tokens can be validated during a rollover window?
- Is there a documented and automated **revocation** path — a denylist / blocklist / kid-deactivation — for when a key is suspected or confirmed leaked?
- Where is the key material persisted? Hard-coded in source, committed in config/env files, sitting in a world-readable file, or fetched from a KMS/HSM/secrets manager?
- Is the JWT `kid` header (or equivalent key selector) resolved against a **fixed allow-list / key map**, or is it interpolated into a path, URL, SQL query, or lookup key?
- Are keys loaded from a JWKS endpoint with signature/cache validation, or fetched ad hoc from an attacker-controllable URL?
- Do symmetric keys meet the ASVS length minimum (e.g. ≥128-bit for HMAC/AES), and are RSA keys ≥2048 / ECC ≥256?
- Is key usage separated by purpose (one key for signing, another for encryption), or is a single key reused across schemes?

## Static signals
Hard-coded / static key material:
- Node/JS: `const SECRET = 'supersecret'`, `jwt.sign(payload, 'shhh')`, `process.env.JWT_SECRET` read once at boot and never rotated.
- Python: `SECRET_KEY = 'change-me'` in `settings.py`, `jwt.encode(payload, 'secret')`, `Fernet(b'fixed32bytes...')`.
- Java: `private static final String KEY = "..."`, `Mac.getInstance("HmacSHA256")` initialised from a literal.
- Go: `var signingKey = []byte("hardcoded")`, `hmac.New(sha256.New, []byte("secret"))`.
- PHP: `define('JWT_SECRET', '...')`, `hash_hmac('sha256', $msg, 'mysecret')`.
- Ruby: `JWT.encode(payload, 'secret', 'HS256')`.

`kid` / key selector resolved unsafely (path traversal / arbitrary lookup):
- `fs.readFileSync('/keys/' + header.kid + '.pem')` / `` fs.readFileSync(`/keys/${kid}.pem`) ``
- `fs.readFileSync('/keys/' + kid)` (no extension, no allow-list)
- Python: `open(f'/keys/{kid}.pem')`, `KEYS_PATH + '/' + kid`
- Java: `new File("/keys/" + kid + ".pem")`, `Files.readAllBytes(Paths.get("/keys/", kid))`
- Go: `os.ReadFile(filepath.Join("/keys", kid))` without `filepath.Clean`/base-name check
- PHP: `file_get_contents("/keys/$kid.pem")`, `openssl_pkey_get_public($kid)`
- Ruby: `File.read("/keys/#{kid}.pem")`

`kid` resolved via SQL / URL / cache key:
- `SELECT key FROM keys WHERE id = '${kid}'` (SQLi via kid)
- `jwksUrl = kid` / `jwksClient.getJwks(kid)` where `kid` is attacker-supplied
- `cache[kid] ?? fetch(kid)` — kid used as an unbounded cache/network key

No rotation / no revocation indicators:
- A single global `JWT_SECRET` constant with no version map, no `current_kid`, no `revoked_kids` set.
- Signature verification that accepts *any* key and never consults a denylist.

## False positives
- A JWKS / kid scheme backed by a KMS or secrets manager, with a documented rotation cadence and a `kid` allow-list — this is the correct pattern, not a finding.
- Short-lived tokens (≤15 min) combined with automated periodic key rotation: the residual risk from a stolen key is bounded, so severity shifts down.
- `kid` is matched against a hard-coded `Map`/object of `{ kid: publicKey }` and any unknown `kid` is rejected — this is the safe resolution pattern.
- Keys live in a managed secret store (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, Azure Key Vault) and the application reloads on rotation signal — no static secret in source.
- The "key" is a public key (verification only) — confidentiality is not at risk, though tampering of the public key source still matters.

## Attack scenario
1. The application verifies JWTs by resolving `kid` as a filename: `fs.readFileSync('/keys/' + header.kid + '.pem')`.
2. Attacker registers their own RSA keypair offline and forges a token signed with their private key, setting the header `{"alg":"RS256","kid":"../../../tmp/attacker_pub.pem"}`.
3. The server resolves the path to the attacker-controlled public key (uploaded via a profile-picture or temp-file feature) and the forged signature validates.
4. The attacker authenticates as any user / arbitrary admin, because the server now trusts a key the attacker created.
5. Alternatively, with a static never-rotated HMAC key: the attacker steals the key from a leaked `.env` or memory dump and mint tokens indefinitely — with no rotation or revocation, the compromise is permanent until every deployed binary/env is updated.

## Impact
- **Confidentiality**: forged tokens grant full access to any account; encryption keys decrypt stored secrets at rest.
- **Integrity**: attacker-signed tokens/JWS are indistinguishable from legitimate ones — arbitrary account takeover, fraudulent transactions, supply-chain payload injection.
- **Availability**: forced global key rotation invalidates all sessions, causing service-wide logouts/outage recovery costs.
- Severity is **Critical** when `kid` is path-resolved (auth bypass on demand) or when the leaked symmetric key has no revocation path. Downgraded to **High/Medium** when rotation exists and blast radius is bounded by short token lifetimes.

## Remediation
Resolve `kid` against an allow-list; never interpolate it into a path, URL, or query.
```ts
// VULNERABLE — kid resolved as a filesystem path (path traversal / arbitrary key)
import fs from 'node:fs';
import jwt from 'jsonwebtoken';
function verify(token) {
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
  const key = fs.readFileSync(`/keys/${header.kid}.pem`); // attacker controls kid
  return jwt.verify(token, key);
}

// SAFE — kid resolved via a fixed key map populated from a KMS/secrets store
import jwt from 'jsonwebtoken';
import { loadKeySet } from './keyStore.js'; // { 'v1': pubKeyV1, 'v2': pubKeyV2 }, refreshed on rotation
const REVOKED = new Set<string>();          // revocation list, updated on leak/rotation
function verify(token) {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header.kid) throw new Error('missing kid');
  if (REVOKED.has(decoded.header.kid)) throw new Error('revoked kid');
  const key = loadKeySet()[decoded.header.kid];   // allow-list lookup only
  if (!key) throw new Error('unknown kid');       // reject unrecognised kid
  return jwt.verify(token, key, { algorithms: ['RS256'] }); // pin algorithm
}
```
Store keys in a managed secrets/KMS store with scheduled rotation and a revocation workflow; load them by `kid` from a versioned key set rather than from source or env files. Defense-in-depth: prefer asymmetric (RS/ES) signing so that verification-key leaks (public keys) are non-critical, pin the accepted `alg` to prevent algorithm confusion, and keep a `revoked_kids` list checked on every verification.

## References
- OWASP ASVS V6.2.x — Cryptographic key lifecycle: generation, storage, rotation, and revocation
- OWASP WSTG-CRYP-04 — Testing for Weak Encryption / Key Management
- OWASP Cheat Sheets: Cryptographic Storage, Secrets Management, JSON Web Token
