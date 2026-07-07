---
id: P51
name: WeakAlgorithms
refs: ASVS V6.2.x / WSTG-CRYP-04 / CS: Cryptographic Storage, Password Storage
---

# P51 — WeakAlgorithms

## Preconditions

The code uses cryptographic functions.


## Overview
Weak or obsolete cryptographic primitives — MD5, SHA-1, DES, 3DES, RC4, and ECB block mode — no longer provide the security margin their use implies. Hashes like MD5/SHA-1 are collision-broken (and SHA-1 is practically collision-feasible), symmetric ciphers with short keys (DES, single-key 3DES) are brute-forceable, RC4 has distinguishable keystream biases, and ECB leaks plaintext structure (identical blocks produce identical ciphertext — the classic "ECB penguin"). The root cause is usually legacy copy-paste, a `Stack Overflow` snippet, or a library default that was reasonable a decade ago but now silently degrades protection. Using these for integrity, tokens, password storage, or data-at-rest encryption converts the algorithm's weakness into a directly exploitable gap.

## What to check
- Is MD5 or SHA-1 used anywhere for a **security purpose** — signature, MAC, token/session ID generation, password storage, integrity check, or HMAC? (Non-security checksums/cache keys are a much lower concern — see False positives.)
- Is the HMAC constructed over a strong hash (SHA-256+), and is it used instead of a bare hash wherever authenticity is required? A bare `SHA-256(data)` proves only integrity of accidental corruption, not authenticity.
- Are symmetric ciphers AES with an authenticated mode (GCM, ChaCha20-Poly1305)? Flag DES, 3DES, RC4, Blowfish for security use, and AES/any cipher in **ECB** mode.
- Are IVs/nonces random and unique per encryption (and for GCM, never reused with the same key)? A static or hardcoded IV under CTR/GCM is catastrophic.
- Is key length adequate — AES-256/ChaCha20 for long-lived secrets; RSA ≥2048; ECDSA/Ed25519 curves (P-256+)?
- Do TLS configurations permit legacy protocols (SSLv3, TLS 1.0/1.1) or weak/NULL cipher suites (RC4, 3DES, EXPORT, NULL, aNULL)?
- Are random numbers for keys/tokens sourced from a CSPRNG (`crypto.randomBytes`, `secrets`, `SecureRandom`), not `Math.random`/`random.random`/`Math.random()`?
- Are passwords stored with a slow KDF (Argon2id, bcrypt, scrypt, PBKDF2 with high iterations), never a plain or salted fast hash (MD5/SHA-256)?

## Static signals
Weak hashes / digest construction:
- Node: `crypto.createHash('md5'|'sha1')`, `crypto.createHash('MD5')`
- Python: `hashlib.md5(...)`, `hashlib.sha1(...)`, `hash.new('sha1')`
- Java: `MessageDigest.getInstance("MD5"|"SHA-1")`, `DigestUtils.md5Hex(...)` / `sha1Hex`
- Go: `md5.Sum`, `sha1.Sum`, `crypto/md5`, `crypto/sha1`
- PHP: `md5()`, `sha1()`, `hash('sha1', ...)`
- Ruby: `Digest::MD5`, `Digest::SHA1`, `OpenSSL::Digest::MD5`
- .NET: `MD5.Create()`, `SHA1Managed`

Weak ciphers / ECB mode:
- Node: `crypto.createCipheriv('aes-128-ecb'|'des'|'des-ede3'|'rc4', key, null)` (ECB takes `null` IV)
- Python: `DES.new`, `ARC4.new`, `AES.new(..., AES.MODE_ECB)`
- Java: `Cipher.getInstance("AES/ECB/...")`, `"DES"`, `"DESede"`, `"RC4"`
- Go: `crypto/des`, `crypto/rc4`; manual ECB block handling
- OpenSSL CLI / config: `openssl enc -des-ecb`, `enc -rc4`

Bare hash used where a MAC is required:
- `crypto.createHash('sha256').update(data)` to sign a token, webhook, or cookie
- `hashlib.sha256(secret + data)` (homebrew MAC — length-extension vulnerable)

Static / hardcoded IV and weak RNG:
- `createCipheriv('aes-256-cbc', key, Buffer.alloc(16))` (zero IV)
- `Math.random()`, `random.random()` used to derive tokens, IDs, or keys
- `uuid` v1/v4 from a non-CSPRNG source

TLS downgrade:
- `secureProtocol: 'TLSv1_method'`, `ciphers: '...RC4...3DES...'`, `rejectUnauthorized: false`
- nginx/Apache: `ssl_protocols SSLv3 TLSv1 TLSv1.1;`, `ssl_ciphers ...RC4...`

## False positives
- MD5/SHA-1 used as a **non-security** checksum: content-addressed cache keys, deduplication, ETag, git blob/object addressing, legacy file fingerprinting. Downgrade to Low / informational, but confirm there is no path where the value is treated as authenticating.
- SHA-256+ for hashing, AES-GCM/ChaCha20-Poly1305 for encryption, HMAC-SHA256+ for authenticity — all safe defaults.
- 3DES/RC4/legacy TLS present only in a `disabled`/commented config block or a compatibility shim that is never negotiated.
- A hash used inside a slow, salted KDF (bcrypt `$2b$`, scrypt, Argon2) — that is correct password storage, not a "weak algorithm".
- ETAG/checksums computed by a framework where the value is only compared for equality and never trusted as authentic.

## Attack scenario
1. A password-reset token is generated as `MD5(userEmail + timestamp)` and emailed in the link.
2. The attacker, who knows the target user's email and can guess the timestamp (second-resolution), precomputes a rainbow table or brute-forces the MD5 offline.
3. The attacker forges a valid reset link, POSTs a new password, and takes over the account — no network position required.
4. Separately, sensitive records are encrypted with AES-ECB: identical PII blocks (e.g. a common SSN prefix, the literal string "CONFIDENTIAL") produce identical ciphertext across records, leaking frequency and structure to anyone with DB read access.

## Impact
- **Confidentiality**: weak ciphers (DES/3DES/RC4) and ECB exposure reveal plaintext or its structure; collision-broken hashes undermine signatures and certificate pinning.
- **Integrity**: MD5/SHA-1 signatures and homebrew MACs can be forged, enabling tampered updates, forged tokens, and bypassed integrity checks.
- **Availability**: low direct impact, though key-recovery or signature forgery can enable broader compromise.
- Severity scales with the asset: a weak hash on a session/reset token or a signing key is High/Critical; on a non-security cache key it is Informational.

## Remediation
Choose algorithms and modes that match modern best practice — authenticated encryption and collision-resistant hashes:
```ts
// VULNERABLE — weak hash for a token, and ECB block mode
const token = crypto.createHash('md5').update(email + Date.now()).digest('hex');
const ct    = crypto.createCipheriv('aes-128-ecb', key, null);

// SAFE — CSPRNG token, AES-GCM authenticated encryption
const token = crypto.randomBytes(32).toString('hex');
const cipher = crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12));
const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
const tag = cipher.getAuthTag(); // store/verify tag on decrypt
```
For authenticity, prefer HMAC-SHA256+ over a secret, or a true AEAD (GCM). Store passwords only through Argon2id/bcrypt/scrypt. Defense-in-depth: disable legacy TLS (minimum TLS 1.2, prefer 1.3) and prune weak cipher suites from every client and server config.

## References
- OWASP ASVS V6.2.x — Cryptographic storage of secrets, keys, and tokens
- OWASP WSTG-CRYP-04 — Testing for weak encryption / weak hash usage
- OWASP Cheat Sheets: Cryptographic Storage, Password Storage, Key Management
