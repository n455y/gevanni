---
id: P54
name: TimingAttack
refs: ASVS V6.2.x / WSTG-CRYP-04 / CS: Cryptographic Storage, Authentication
---

# P54 — Timing Attack

## Preconditions

The code compares values for security decisions.


## Overview
A timing (side-channel) attack recovers a secret by measuring how long a comparison or decryption takes. When secret values — tokens, HMACs, password hashes, API keys, CAPTCHA/OTP codes, password-reset tokens — are validated with ordinary short-circuiting equality (`===`, `==`, `strcmp`, `equals`), the response time correlates with the number of leading bytes that match. An attacker submits guesses, statistically averages the noisy timing samples, and recovers the secret one byte at a time. The root cause is always data-dependent control flow or memory access over secret-dependent data: comparison loops that return on the first mismatch, character-wise early-exit checks, or non-constant-time cryptographic primitives. Even a few microseconds of variance is exploitable over a network with enough samples.

## What to check
- Are secrets compared with normal equality operators — `===`, `==`, `Object.is`, `Buffer#equals` in some loops, Java `String.equals`, Python `==`, Go `==`, PHP `===`, Ruby `==`?
- Is an HMAC, signature, JWT MAC, or webhook signature verified with `===`/`equals` instead of a constant-time compare?
- Are password-reset tokens, email-verification tokens, OTP/TOTP codes, or CAPTCHA answers checked via early-return string comparison?
- Does authentication short-circuit on username lookup failure (no such user) before password verification, leaking which usernames exist via timing?
- Is there secret-dependent branching (`if (key[i] !== guess[i]) return`) or secret-dependent array indexing (table lookups indexed by key bytes)?
- Are MD5/SHA hashes compared byte-by-byte, or via `MessageDigest.isEqual` in older Java versions (fixed to constant-time only in JDK 6u17)?
- Does the code call `==` on two `byte[]`/`Buffer`/`[]byte` arrays that hold secret material?
- Is the password hash verified with a non-constant-time comparison instead of the library's own verify function?

## Static signals
Secret compared with ordinary equality:
- Node/JS: `if (token === expected)`, `userToken == dbToken`, `apiSecret === process.env.SECRET`
- JS: `Buffer.compare(a, b) === 0` is constant-time, but `a.equals(b)` over secret bytes with naive loops is suspect
- Python: `if token == stored:`, `hmac_digest == expected`, `secrets`-less comparison
- Python: missing `hmac.compare_digest(a, b)`
- Java: `expected.equals(token)`, `new String(mac).equals(received)`, `Arrays.equals` over secret `byte[]` (acceptable) vs `String.equals` (not)
- Java: `MessageDigest.isEqual(a, b)` in pre-6u17 JDKs (non-constant-time)
- Go: `if subtle.ConstantTimeCompare(mac, sum) != 1` (correct) vs `if bytes.Equal(mac, sum)` (vulnerable) or `hmac.Equal` (correct, constant-time)
- PHP: `if ($token === $user->reset_token)`, `hash_equals($expected, $received)` is the safe form
- Ruby: `if token == stored`, missing `Rack::Utils.secure_compare` / `OpenSSL.fixed_length_secure_compare`
- C#: `if (token == stored)`, missing `CryptographicOperations.FixedTimeEquals` / `FixedTimeEquals`

HMAC/signature/JWT verification:
- `crypto.createHmac(...).digest('hex') === req.headers['x-signature']`
- Webhook signature checked with `===` instead of `crypto.timingSafeEqual`
- JWT library `verify` bypassed by manual `header.payload === expected` comparison

Authentication timing leaks:
- "User not found" path returns immediately; "wrong password" path runs the full hash comparison — username enumeration
- OTP/CAPTTCHA validated with `if (req.body.code === user.otpCode)`

## False positives
- Comparison uses a constant-time primitive: Node `crypto.timingSafeEqual(a, b)` (with equal-length guard), Python `hmac.compare_digest`, Go `subtle.ConstantTimeCompare` / `hmac.Equal`, PHP `hash_equals`, Java `MessageDigest.isEqual` (modern JDK) or `Arrays.equals` over fixed `byte[]` used with a constant-time wrapper, .NET `CryptographicOperations.FixedTimeEquals`, Ruby `OpenSSL.fixed_length_secure_compare`.
- The compared value is public/non-secret (a published hash, an enum, a user-facing ID) — timing leakage is low/no impact.
- The secret has high entropy and is single-use with tight expiry (e.g., one-shot OTP) and is rate-limited — practical recovery becomes infeasible even with timing leakage, reducing severity.
- The comparison is between two internally generated values inside a trusted boundary, not reachable by an external requester.
- A low-entropy value (e.g., 4-digit PIN) compared with ordinary equality — timing attack is theoretically possible but the real risk is brute force; ensure rate limiting instead.

## Attack scenario
1. Attacker targets a password-reset endpoint that does `if (req.body.token === user.resetToken)`.
2. Attacker requests a reset for a known account and obtains the victim's reset token URL prefix; the token is hex.
3. Attacker iterates the first byte (00–ff), sending 256 candidate tokens many times each and averaging response latency. The byte that matches the secret's first byte takes marginally longer (comparison proceeds to byte 2 before failing).
4. Once the first byte is identified by its consistently elevated mean time, the attacker fixes it and repeats for byte 2, then byte 3 — each round adds one known byte.
5. After recovering the full token, the attacker resets the victim's password and takes over the account. Total requests scale with `256 * token_length * samples_per_byte`, feasible on a quiet endpoint.

## Impact
- **Confidentiality**: full recovery of tokens, HMAC keys, OTP seeds, API secrets, or password hashes — leading to account takeover, session forgery, or webhook signature forgery.
- **Integrity**: forged tokens/HMACs let the attacker impersonate users or sign malicious requests.
- **Availability**: usually not affected directly, though token reset forgery can lock out legitimate users.
- Severity scales with secret value and recovery cost: a long-lived API key or signing secret is Critical; a single-use, short-TTL OTP is Low–Medium. Timing attacks are noisy over the network but reliable on co-located or low-latency targets (same cloud region, localhost sidecar).

## Remediation
Always compare secrets with a constant-time primitive of the correct length, and keep failure paths uniform:
```ts
// VULNERABLE — short-circuiting equality on a secret
app.post('/reset', (req, res) => {
  if (req.body.token === user.resetToken) return ok();
  return deny();
});

// SAFE — constant-time comparison with length guard
import crypto from 'node:crypto';
const a = Buffer.from(String(req.body.token));
const b = Buffer.from(String(user.resetToken));
if (a.length === b.length && crypto.timingSafeEqual(a, b)) return ok();
return deny();
```
```python
# VULNERABLE
if token == stored_token:
    grant()

# SAFE
import hmac
if hmac.compare_digest(token.encode(), stored_token.encode()):
    grant()
```
Normalize authentication latency: always run a full password-hash verification (e.g., with a dummy hash) even when the username is unknown, so "user not found" and "wrong password" take the same time — defense-in-depth against username enumeration.

## References
- ASVS V6.2.x
- WSTG-CRYP-04
- CS: Cryptographic Storage, Authentication
