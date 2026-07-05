---
id: P53
name: IVNonceSalt
refs: ASVS V6.2.x / WSTG-CRYP-04 / CS: Cryptographic Storage, Password Storage
requires: [backend]
---

# P53 — IVNonceSalt

## Overview
Symmetric ciphers in authenticated modes (AES-GCM, ChaCha20-Poly1305) and password hashes / key-derivation functions (PBKDF2, scrypt, Argon2) all rely on a value that must never repeat or be omitted under a given key: the **initialization vector (IV) / nonce** for stream-style encryption, and the **salt** for password hashing. Reusing a nonce with the same key in GCM/ChaCha20 is catastrophic — it leaks the authentication key and enables plaintext recovery and forgery — while an omitted or constant salt makes password hashes trivially vulnerable to precomputed (rainbow-table) and multi-target dictionary attacks. The root cause is almost always developer error: a hardcoded IV/nonce (`Buffer.alloc(12, 0)`), a non-cryptographic RNG (`Math.random`), or a KDF called without its salt argument.

## What to check
- Is a fresh, cryptographically random IV/nonce generated **per encryption** and stored alongside the ciphertext (never secret, but never reused)?
- Is the IV/nonce hardcoded, constant, derived from predictable state (counter that resets, timestamp only, message index with no rollover guard)?
- For AES-GCM/ChaCha20-Poly1305: can the same key+nonce pair ever occur twice? (The single most dangerous property of these modes.)
- For CBC: is the IV predictable before the attacker chooses plaintext? (Predictable CBC IV enables chosen-plaintext padding/chosen-plaintext block manipulation.)
- Is the IV sourced from `Math.random`, `Math.random().toString()`, a UUID v4 generator that is not crypto-backed, or `random.randint`?
- Are passwords hashed/derived with a KDF (`scrypt`, `argon2`, `pbkdf2`) that **omits the salt**, uses a constant salt, or uses a per-user value that is not random (e.g. username)?
- Is the salt long enough (>= 16 bytes / 128 bits) and freshly generated per credential?
- Are legacy constructions in use — `MD5`/`SHA1`/`SHA256(pw)`, `crypt()` with DES, `ECB` mode, `createCipher` (auto-IV, deprecated in Node) — that have no salt or IV at all?

## Static signals
Hardcoded / constant IV or nonce:
- `Buffer.alloc(12, 0)`, `Buffer.from('000000000000000000000000', 'hex')`, `new byte[12]`, `iv = b'\x00' * 12`, `[]byte{0,0,0,0,0,0,0,0,0,0,0,0}`
- `createCipheriv('aes-256-gcm', key, STATIC_IV)`, `Cipher.getInstance("AES/GCM/NoPadding")` with a fixed `GCMParameterSpec` IV
- Go: `gcm.Seal(nil, nonce, plaintext, nil)` where `nonce := []byte{...}` is reused

Non-cryptographic RNG used as IV:
- Node: `Math.random().toString(36)` → IV, `Date.now()` → nonce
- Python: `random.randint`, `random.randbytes` (NOT `secrets`/`os.urandom`)
- Java: `new Random()` vs `SecureRandom`
- PHP: `rand()`, `mt_rand()`, `uniqid()` vs `random_bytes(12)` / `openssl_random_pseudo_bytes()`
- Ruby: `rand` vs `SecureRandom.random_bytes`

Saltless / constant-salt KDF:
- Node: `crypto.scrypt(password, '', ...)` (empty salt), `crypto.createHash('sha256').update(password)` (no salt, no KDF)
- Python: `hashlib.sha256(pw.encode()).hexdigest()`, `hashlib.pbkdf2_hmac('sha256', pw, b'', iters)` (empty salt)
- Java: `MessageDigest.getInstance("SHA-256").digest(pw.getBytes())`, `PBKDF2WithHmacSHA256` with a literal salt
- PHP: `md5($pw)`, `sha1($pw)`, `hash('sha256', $pw)`, `password_hash` with `PASSWORD_DEFAULT` is SAFE (auto-salt)
- Ruby: `Digest::SHA256.hexdigest(pw)`, `OpenSSL::KDF.pbkdf2_hmac(pw, salt: '')`

Deprecated / unsafe primitives:
- Node `crypto.createCipher` / `createDecipher` (deprecated: derives IV internally, weak)
- ECB mode: `Cipher.getInstance("AES/ECB/...")`, `createCipheriv('aes-256-ecb', ...)`
- Predictable CBC IV set to a constant or a low-entropy counter

## False positives
- The IV/nonce is freshly generated with a CSPRNG for every encryption (`crypto.randomBytes`, `secrets.token_bytes`, `SecureRandom.generateSeed`, `random_bytes`, `SecureRandom.random_bytes`) and stored alongside ciphertext — nonces are public, only uniqueness matters.
- A correctly-implemented **counter-based** nonce scheme where the counter is persisted, monotonic, never resets, and the key is rotated before any rollover (common in sealed-box / record-per-message designs).
- The "salt" is a per-row random value stored in a separate column and verified to be unique per user (e.g. Django's `make_password`, Laravel `Hash::make`, Rails `has_secure_password` all generate and embed a random salt internally).
- Synchronous envelope encryption where a data-encryption-key wraps a random per-message DEK with its own fresh nonce (still must not reuse the wrapping key+nonce).

## Attack scenario
1. The app encrypts audit records with AES-256-GCM using a hardcoded 12-byte zero IV and a single long-lived key.
2. The attacker captures two ciphertexts `C1, C2` encrypted under the same key+nonce — e.g. an API response and a follow-up retransmission, or two rows from a leaked DB dump.
3. Identical nonces in GCM XOR the two keystreams: `P1 ⊕ P2 = C1 ⊕ C2`. The attacker recovers plaintext by crib-dragging, and the GCM authentication key (`H`) leaks, enabling **forgery** of any future message under that key.
4. Separately, password DB rows use `sha256(password)` with no salt. The attacker runs a GPU dictionary against the whole table in one pass (one hash per guess tests every account), and precomputed rainbow tables resolve common passwords instantly.

## Impact
- **Confidentiality**: nonce reuse in a stream/CTR/GCM mode leaks plaintext (two-time-pad); unsalted password hashes succumb to rainbow tables and amortized dictionary attacks across all accounts.
- **Integrity**: GCM/ChaCha20-Poly1305 nonce reuse reveals the auth subkey, allowing undetected ciphertext forgery and authentication-bypass.
- **Availability**: forgery can corrupt encrypted sessions or tokens, forcing mass invalidation / rotation.
- Severity is **Critical** for nonce reuse in an AEAD mode (key recovery territory) and **High** for unsalted or weakly-salted password storage; CBC with a predictable IV is High when the attacker can influence plaintext.

## Remediation
Generate a fresh CSPRNG IV/nonce per message and store it with the ciphertext; salt every password hash:
```ts
// VULNERABLE — hardcoded zero IV (catastrophic under GCM key reuse)
const iv = Buffer.alloc(12, 0);
const c = crypto.createCipheriv('aes-256-gcm', key, iv);

// VULNERABLE — saltless password hash (rainbow-table / multi-target)
const h = crypto.createHash('sha256').update(password).digest('hex');

// SAFE — fresh random nonce stored with ciphertext; salted KDF for passwords
import { randomBytes, scryptSync, timingSafeEqual } from 'crypto';

const nonce = randomBytes(12);                         // new per message
const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
const tag = cipher.getAuthTag();
// store: nonce || tag || ct   (nonce/tag are public; key stays secret)

const salt = randomBytes(16);                          // new per user
const derived = scryptSync(password, salt, 32, { N: 2**15, r: 8, p: 1 });
// store: salt || derived  (verify with timingSafeEqual; never recompute unsalted)
```
Defense-in-depth: rotate keys well before any counter/nonce space approaches collision (GCM limits to ~2^32 messages per key), prefer AEAD modes, and prefer a vetted library (libsodium `crypto_secretbox`/`crypto_aead`, `argon2id`) over hand-rolled crypto.

## References
- OWASP ASVS V6.2.x — Cryptographic key management, IV/nonce and salt requirements
- OWASP WSTG-CRYP-04 — Testing for Weak Encryption / predictable IVs
- OWASP Cheat Sheets: Cryptographic Storage, Password Storage, Key Management
