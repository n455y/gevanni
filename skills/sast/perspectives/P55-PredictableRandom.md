---
id: P55
name: PredictableRandom
refs: ASVS V6.3.x / WSTG-CRYP-04 / CS: Cryptographic Storage
---

# P55 — PredictableRandom

## Preconditions

The code generates random values.


## Overview
Predictable randomness is the use of a non-cryptographic pseudo-random number generator (PRNG) — `Math.random()`, `rand()`, LCGs, time/microsecond seeds — to produce values that are supposed to be unguessable: session IDs, tokens, CSRF nonces, password-reset codes, OTPs, API keys, or any short-lived secret. The root cause is treating "random-looking" output as "unguessable." Non-crypto PRNGs have small internal state and observable output; given a few tokens an attacker can reconstruct the generator's state and predict every past and future value. The result is a complete collapse of authentication boundaries — account takeover, session hijacking, and one-time-token forgery.

## What to check
- Are session IDs, bearer tokens, CSRF tokens, password-reset tokens, email-verification codes, OTPs/2FA codes, anti-CSRF state parameters, or any "unguessable" identifier generated with a cryptographically secure RNG (CSPRNG)?
- Is the output long enough? Tokens should carry at least 128 bits of entropy (e.g. `randomBytes(32)` → 256 bits); 6–8 digit OTPs are acceptable only when paired with throttling/expiry and a high-entropy seed.
- Is the RNG seeded from a weak source — system time (`Date.now()`), process PID, a hardcoded constant, or `srand(time(0))`? A predictable seed defeats a strong algorithm.
- Is a general-purpose PRNG (`java.util.Random`, Python's `random` module, Go's `math/rand`, PHP `rand()`/`mt_rand()`, Ruby `rand`) used anywhere a secret is produced?
- Are UUIDs used as security tokens? Plain UUIDv4 from a CSPRNG is acceptable, but `uuid1()` leaks the MAC address and timestamp, and non-RFC-4122 "unique IDs" built from `Date.now()+counter` are predictable.
- Are short reset/OTP codes throttled (attempt limits) and time-boxed? Short entropy is survivable only with rate limiting.
- Does the token get logged, returned in a URL query string, or cached — exposing it regardless of RNG strength?

## Static signals
Non-crypto PRNG producing tokens / IDs / nonces / secrets:
- Node/JS: `Math.random()` used for tokens — `Math.random().toString(36).slice(2)`, `Math.random().toString(16)`, `crypto.randomBytes` absent from the token path.
- Python: `random.randint`, `random.choice`, `random.random`, `random.getrandbits`, `random.seed` in modules that issue tokens; should be `secrets.token_urlsafe`/`token_hex` or `os.urandom`.
- Java: `new java.util.Random()`, `Math.random()`, `ThreadLocalRandom.current()` for IDs/tokens; should be `SecureRandom`.
- Go: `math/rand` / `rand.Intn` / `rand.Read` (non-crypto) for secrets; should be `crypto/rand`.
- PHP: `rand()`, `mt_rand()`, `uniqid()` (no entropy by default), `lcg_value()`; should be `random_bytes()` / `random_int()`.
- Ruby: `rand`, `Array#sample` (non-crypto), `SecureRandom` missing; should be `SecureRandom.hex/urlgen/random_bytes`.
- C/C++: `rand()`, `srand(time(NULL))`, `drand48()`, custom LCG; should be `getrandom()`/`/dev/urandom`.
- .NET: `new Random()`, `Random.Shared`; should be `RandomNumberGenerator.GetBytes()` / `BCryptGenRandom`.

Weak / predictable seeding:
- `Math.random()` and `rand()` implicitly seeded from time/PID — always weak.
- Explicit `srand(time(0))`, `random.seed(datetime.now())`, `Random(seed=pID)`, `rand.Seed(time.Now().UnixNano())`.
- Hardcoded seeds: `srand(0x1234)`, `new Random(42)`.

Insufficient entropy / format:
- `Math.random().toString(36).slice(2)` (≈52 bits, often less).
- `Date.now().toString(36)` (timestamp — trivially guessable).
- Token shorter than 16 hex chars (≈32 bits or less).
- `uniqid()` / `uniqid('', true)` in PHP used as a session or reset token.

## False positives
- The value is genuinely non-security: UI placeholder text, a test-data factory, a shuffled display order, a dice-game animation, or a CAPTCHA challenge image name with a short server-side TTL and no account impact. Rate as Low or skip.
- A CSPRNG is already in use — Node `crypto.randomBytes`/`crypto.randomUUID()`, Python `secrets.*`/`os.urandom`, Java `SecureRandom`, Go `crypto/rand`, PHP `random_bytes`/`random_int`, Ruby `SecureRandom`, .NET `RandomNumberGenerator`. Verify the bytes are actually consumed on the token path, not bypassed.
- UUIDv4 generated via a CSPRNG (e.g. Node `crypto.randomUUID()`, Python `uuid.uuid4()` backed by `os.urandom`) for non-secret correlation IDs — acceptable, though not a substitute for an unguessable bearer token.
- Short OTPs are throttled (e.g. ≤5 attempts / 10 min) and expire quickly, and the underlying generator is a CSPRNG — entropy is intentionally bounded and protected.

## Attack scenario
1. The app issues password-reset tokens via `const token = Math.random().toString(36).slice(2)`.
2. The attacker requests a reset for the victim and receives nothing, but knows `Math.random()` is a xorshift/Feedback-LCG with ~52 bits of state.
3. The attacker triggers two more resets of their own account and observes (from the reset links emailed to themselves) several consecutive `Math.random()` outputs.
4. Using the z3 solver or a published V8/xorshift128+ state-recovery script, the attacker reconstructs the internal state and computes the token that was issued to the victim.
5. The attacker submits `https://app/reset?token=<predicted>` within the validity window and resets the victim's password — full account takeover without ever touching the victim's device.

## Impact
- **Confidentiality**: session/cookie/token disclosure enables impersonation; password-reset/OTP forgery exposes private data and resets credentials.
- **Integrity**: forged tokens let the attacker change passwords, confirm email addresses, authorize transactions, or mint admin sessions.
- **Availability**: predictable anti-CSRF state parameters or rate-limit nonces can be enumerated, enabling lockout or replay floods.
- Severity scales with what the token authorizes: a 6-digit OTP is Medium when throttled, Critical when unthrottled; a `Math.random()` session ID is Critical because session-state recovery compromises all users.

## Remediation
Use the platform CSPRNG and emit enough bytes for the use case:
```ts
// VULNERABLE — predictable PRNG, low entropy
const token = Math.random().toString(36).slice(2);

// SAFE — cryptographically secure, 256 bits
import { randomBytes } from 'node:crypto';
const token = randomBytes(32).toString('base64url');
```
```python
# VULNERABLE
import random
token = ''.join(random.choice('0123456789') for _ in range(6))   # seeded from time

# SAFE
import secrets
token = secrets.token_urlsafe(32)               # bearer token
otp   = str(secrets.randbelow(1_000_000)).zfill(6)   # 6-digit OTP, CSPRNG-backed
```
Defense-in-depth: pair short OTPs with strict attempt throttling and short expiry, never log or place tokens in URLs, and rotate session secrets on a schedule.

## References
- OWASP ASVS V6.3.x — Cryptographic key management and random number generation requirements
- OWASP WSTG-CRYP-04 — Testing for Weak or Predictable Random Values
- OWASP Cheat Sheet: Cryptographic Storage, plus OWASP Top 10 A02 (Cryptographic Failures) guidance on random generation
