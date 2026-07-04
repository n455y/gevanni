---
id: P7
name: PasswordHashing
area: V6 Authentication
refs: ASVS V2.4.x / WSTG-ATHN-07 / CS: Password Storage
---

# P7 — Password Hashing

## Overview
Password hashing is the process of transforming a plaintext password into an irreversible, salted, deliberately slow value before storage. The goal is not confidentiality of a reusable secret — the user must be able to re-authenticate — but to make bulk offline cracking computationally infeasible if the credential store is ever dumped. The root cause of weakness is almost always one of: a fast general-purpose hash (MD5/SHA-1/SHA-256) used without a salt, no salt at all, a reversible cipher (AES) that lets the operator recover the original, or a deliberately-slow KDF invoked with parameters far below current guidance. Because a database leak is treated as inevitable in threat modeling, the hash is the last line of defense.

## What to check
- Are passwords stored as plaintext or in any reversible form (AES/3DES encryption, base64, hex), even if "encrypted with a server key"?
- Is a deliberately slow, salted KDF used — bcrypt, scrypt, Argon2id, or PBKDF2 — rather than a fast cryptographic hash (MD5, SHA-1, SHA-256, SHA-512) applied directly?
- Is a per-user random salt present, and is it stored alongside (not secret) the hash? A hardcoded/global salt defeats the purpose.
- Are the cost/iteration parameters above current OWASP floors? bcrypt cost ≥ 10 (target ≥ 12), scrypt N ≥ 2¹⁵ with reasonable r/p, Argon2id m ≥ 19 MiB / t ≥ 2 / p ≥ 1, PBKDF2-HMAC-SHA256 ≥ 600000 iterations (≥ 210000 for SHA-1).
- Is pepper used (HMAC or KDF over a secret held outside the DB) where feasible, and is the pepper managed in a KMS/HSM, not checked into source?
- Does the code compare hashes with a constant-time comparison (`timingSafeEqual`, `hash_equals`, `compare_digest`) rather than `==`/`!=`?
- Are plaintext passwords written to logs, exceptions, audit trails, APM spans, or returned in API responses?
- During login, is the hash recomputed and compared server-side, or does any path accept a client-side hash as the authenticator (passing the buck)?

## Static signals
Fast hash applied to a password (no KDF):
- `md5(`, `sha1(`, `sha256(`, `sha512(` near a `password` / `pwd` / `passwd` / `credential` variable.
- Node: `crypto.createHash('md5'|'sha1'|'sha256').update(password).digest('hex')`.
- Python: `hashlib.md5(password.encode()).hexdigest()`, `hashlib.sha256(pw).hexdigest()` (no `pbkdf2_hmac`/`passlib`/`bcrypt`/`argon2` in scope).
- Java: `MessageDigest.getInstance("SHA-256")` then `.digest(password.getBytes())`; Spring `BCryptPasswordEncoder` absent.
- Go: `sha256.Sum256([]byte(password))`, `md5.Sum`.
- PHP: `md5($password)`, `sha1($password)`, `hash('sha256', $pw)`; legacy `crypt()` with a DES/MD5 salt.
- Ruby: `Digest::SHA256.hexdigest(password)`; Rails without `has_secure_password` / `bcrypt`.

Reversible or plaintext storage:
- AES encrypt of password: `crypto.createCipheriv('aes-256-gcm', key, iv)` over a password; Java `Cipher.getInstance("AES")`; PHP `openssl_encrypt($pw, 'aes-256-cbc', ...)`.
- `storedPassword = password`, `user.password = req.body.password` persisted via ORM without hashing.
- base64: `Buffer.from(password).toString('base64')`, `base64_encode($pw)`.

Weak parameters on an otherwise-correct KDF:
- bcrypt cost `< 10`: `bcrypt.hash(password, 8)`, `BCrypt.gensalt(4)`, `$2a$04$`, `$2y$06$`.
- scrypt weak: `scrypt.hash(pw, N=1024, r=8, p=1)`; Go `scrypt.Key(pw, salt, 1<<10, ...)`.
- PBKDF2 low iterations: `pbkdf2(password, salt, 1000, ...)`, `pbkdf2_hmac('sha256', pw, salt, 10000)`.
- Argon2 weak: `memoryCost` < 19456, `timeCost: 1`, `parallelism: 1`.

Hardcoded / global salt and non-constant-time compare:
- `SALT = 'abc123'` reused for all users; `crypto.randomBytes` for salt absent.
- `if (user.hash === reqHash)`, `hash === stored`, `$row['hash'] == $input` (PHP loose compare).
- `md5($password) === $stored` — fast hash AND non-constant-time.

Leakage:
- `console.log('login', password)`, `logger.info("auth pw=" + pw)`, `throw new Error('bad pw ' + password)`.

## False positives
- bcrypt/Argon2id/scrypt/PBKDF2 invoked through a maintained library with parameters at or above OWASP floors (e.g. `bcrypt.hash(pw, 12)`, `argon2.hash(pw, {type: argon2id, memoryCost: 19456, timeCost: 2})`, Rails `has_secure_password`, Django `make_password`/`set_password`, Spring `BCryptPasswordEncoder`, PHP `password_hash($pw, PASSWORD_DEFAULT)`).
- Fast hash of a *non-password* value — file checksums, cache keys, HMAC over an API token, integrity tags. Confirm the hashed variable is actually a credential before flagging.
- A migration path that verifies the old weak hash and transparently re-hashes with bcrypt/Argon2 on next successful login — this is the correct remediation pattern (flag as Medium, not High, while the legacy hashes still exist).
- Hashing that is intentionally fast because the input is already a high-entropy client-side challenge response; confirm the server never sees a reusable password.
- Verifying (not storing) a password against an upstream system via an opaque API (`ldap_bind`, RADIUS) — hashing happens remotely.

## Attack scenario
1. Attacker obtains a copy of the users table via SQL injection, a misconfigured backup bucket, an insider, or a dumped dev database.
2. The dump reveals `password` values like `5f4dcc3b5aa765d61d8327deb882cf99` (MD5 of "password"), unsalted SHA-256, or AES ciphertext recoverable with a hardcoded key found in the same repo.
3. Because the hashes are fast and/or unsalted, the attacker runs a GPU rig (billions of MD5/sec) or a precomputed rainbow table. Unsalted MD5/SHA cracks in seconds; even salted SHA-256 falls to dictionary attacks at scale.
4. For each cracked account, the attacker tries the recovered password against the app's login, email provider, and other services — password reuse turns one crack into many compromises, including admin accounts whose hashes were in the same dump.
5. Even reversible "encryption" yields plaintext immediately once the key leaks, exposing every user with zero cracking cost.

## Impact
- **Confidentiality**: mass disclosure of user passwords; password reuse cascades into email, banking, and SSO accounts.
- **Integrity**: attackers authenticate as any cracked user (including admins), modify data, create backdoor accounts.
- **Availability**: destructive actions under compromised admin creds (delete records, disable tenants).
- Severity scales with the crackability: plaintext/AES/reversible = Critical; unsalted fast hash = High; salted fast hash or weak KDF params = High/Medium; compliant Argon2id/bcrypt at OWASP floors = informational. The blast radius compounds with password reuse across the user base.

## Remediation
Use a deliberately slow KDF with a per-user salt and OWASP-recommended parameters; never store plaintext or fast-hash a password:
```ts
// VULNERABLE — fast hash, no salt, non-constant-time compare
import { createHash } from 'crypto';
const stored = createHash('sha256').update(password).digest('hex');
if (stored === user.hash) { /* login */ }

// SAFE — Argon2id with per-user salt (embedded in the hash string) and constant-time verify
import argon2 from 'argon2';
const stored = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 19456, // 19 MiB
  timeCost: 2,
  parallelism: 1,
});
if (await argon2.verify(user.hash, password)) { /* login */ }
```
Where Argon2id is unavailable, bcrypt (cost ≥ 12) or PBKDF2-HMAC-SHA256 (≥ 600000 iterations) are acceptable fallbacks. Add a server-side **pepper** (HMAC over the password before hashing) held in a KMS/HSM as defense-in-depth so that a database leak alone is insufficient to begin cracking — and transparently re-hash legacy credentials on each successful login to retire weak storage over time.

## References
- OWASP ASVS V2.4.x — Password Storage and credential lifecycle requirements
- OWASP WSTG-ATHN-07 — Testing for Weak Password Storage / Password Hashing
- OWASP Cheat Sheet: Password Storage
- NIST SP 800-63B §5.1.1 — Memorized Secret Verifiers (key derivation, rate limiting)
