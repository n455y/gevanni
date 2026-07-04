---
id: P67
name: MemoryClearing
area: V14 Data Protection
refs: ASVS V8.x / WSTG-CRYP-04 / CS: Sensitive Data Protection
---

# P67 — MemoryClearing

## Overview
Sensitive secrets — plaintext passwords, cryptographic keys, session tokens, payment card data (PAN/CVV), and private keys — frequently linger in process memory long after they are needed. Garbage-collected runtimes (Node, Python, Java, Go, .NET) make this worse: strings are immutable and interned, GC collection is non-deterministic, and the heap can be paged to swap or captured by a core dump, heap snapshot, or `/proc/<pid>/mem` read. The root cause is treating secret lifetime as "until the process exits" rather than scoping it to the minimum window required for use, then explicitly zeroing the buffer. ASVS V8 requires that sensitive data in memory be minimized, ephemeral, and cleared as soon as practical.

## What to check
- Are plaintext passwords/keys/tokens retained as object fields, module-level variables, singletons, or in a cache (Redis, LRU, in-memory session store) beyond the call that needs them?
- Is a secret stored as an **immutable string** (immutable, cannot be wiped) when a mutable byte buffer would allow explicit zeroing?
- After deriving a key (PBKDF2/scrypt/HKDF) or decrypting a payload, is the intermediate plaintext buffer cleared, or does it stay referenced until GC?
- Are secrets written to logs, error traces, APM spans, heap snapshots, or core dumps (check `--heapsnapshot-signal`, `ulimit -c`, error reporters)?
- Does the application disable core dumps (`RLIMIT_CORE` / `prctl(PR_SET_DUMPABLE, 0)`) and avoid swap for secret-handling pages (`mlock`) where the OS/runtime supports it?
- Are card CVVs / full PANs held in memory when a tokenization scheme or masked PAN would suffice?
- In Node, are crypto secrets passed via `Buffer`/`TypedArray` and `.fill(0)`'d in a `finally`, or do they pass through `string` (immutable)?
- In Python, is `ctypes.memset`/`bytearray` used for secrets, with `__del__`/context-manager zeroing, instead of `str`?

## Static signals
Long-lived secret references:
- Node: `this.password = ...`, `const KEY = fs.readFileSync('privkey.pem')` at module scope, `cache.set(token, secret)`, `user.password = hash` (storing plaintext on the model).
- Python: `self._api_key = key`, class-level `SECRET = os.environ[...]`, `@lru_cache` over a function returning plaintext.
- Java: `private static final String KEY = ...`, fields on `@Singleton` EJBs / Spring `@Component` beans holding decrypted values.
- Go: package-level `var signingKey []byte`, `sync.Pool` reusing secret buffers without wiping.

Immutable string used for secrets (cannot be zeroed):
- Node: `const pwd = req.body.password` (string), `crypto.createHmac('sha256', password)` with a string.
- Python: `pwd = request.form['password']` (`str`), `token = environ['HTTP_AUTHORIZATION']`.
- Java/Ruby/PHP: `String`/`String`/`string` secrets — immutable by design.

Missing/incorrect cleanup:
- `Buffer.from(secret)` without a matching `buf.fill(0)` in `finally` (zeroing skipped on throw).
- `subtle.crypto.deriveBits(...)` result kept as a long-lived `ArrayBuffer` never overwritten.
- `mlock`/`secure_zero_memory` absent in C extensions or native modules that hold keys.

Leak surfaces:
- `console.log(req.body)`, `log.error('auth failed', { password })`, Sentry/Bugsnag breadcrumbs capturing request bodies.
- `--heapsnapshot-signal=SIGUSR2`, `v8.writeHeapSnapshot()`, `/proc/self/mem`, `gcore`, `jmap -dump` reachable from ops/debug routes.

## False positives
- The runtime genuinely cannot guarantee zeroing (most managed runtimes don't); mitigations like minimum scope + short lifetime reduce severity to Medium rather than Low — do not dismiss outright.
- A `Buffer.fill(0)`/`memset`/`crypt.ZERORNG` pattern paired with immediate scope exit and no retained reference is already the safe pattern — verify the `finally` actually runs on all throw paths.
- Secrets that are public-by-nature (certificates, public keys, non-secret configuration) need not be zeroed.
- HSM/TPM/KMS-backed keys that never enter process memory are out of scope — the secret is in the hardware.
- Test fixtures and mock secrets with no real-world value are not exploitable.

## Attack scenario
1. The target runs a Node/Java service that decrypts a database column key at startup and keeps the plaintext `byte[]`/`Buffer` in a singleton field.
2. An attacker with low-privilege code execution on the host (SSRF to a file-read primitive, container escape read, or a co-tenant side process) reads `/proc/<pid>/maps` + `/proc/<pid>/mem` and scans the heap for high-entropy / key-shaped data.
3. Alternatively, a memory leak or OOM triggers a core dump (`ulimit -c` unbounded) written to a world-readable path, or an operator takes a heap snapshot (`SIGUSR2`) that ends up in an artifact store.
4. The attacker extracts the column key, decrypts the database-at-rest, and reads all protected records — bypassing the application entirely.

## Impact
- **Confidentiality**: disclosure of plaintext credentials, encryption keys, tokens, and card data. A single leaked master/key-encryption key cascades to all data encrypted under it.
- **Integrity**: stolen signing keys enable forged tokens, signed updates, or impersonation.
- **Availability**: indirect — key compromise forces rotation and revocation, taking services offline.
- Severity scales with secret value: an in-memory DB encryption key or payment CVV is High/Critical; a short-lived request password retained briefly is Medium; an already-hashed value is informational.

## Remediation
Hold secrets in mutable, zeroable buffers scoped to the narrowest possible block and wipe them in a `finally`:
```ts
// VULNERABLE — immutable string, retained on the object, never cleared
class AuthService {
  password: string;                       // immutable, GC'd unpredictably
  async login(reqBody) {
    this.password = reqBody.password;     // leaks past the call
    const ok = await verify(this.password);
    return ok;
  }
}

// SAFE — Buffer, scoped locally, zeroed in finally
import { timingSafeEqual } from 'node:crypto';

async function login(reqBody: { password: string }) {
  const buf = Buffer.from(reqBody.password, 'utf8');
  try {
    return await verify(buf);
  } finally {
    buf.fill(0);                          // wipe regardless of throw
  }
}
```
```python
# Python: mutable bytearray wiped on exit
import ctypes

def use_secret(secret: str):
    buf = bytearray(secret, 'utf-8')
    try:
        return do_work(buf)
    finally:
        ctypes.memset(
            (ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf)
        )
```
Defense-in-depth: disable core dumps and reduce swap exposure for secret-handling processes (`RLIMIT_CORE`/`prlimit`, `mlock`/`MALLOC_PERTURB_`, container `--memory-swappiness=0`), and scrub secrets from logs/error reporters via redaction filters. On runtimes that cannot guarantee zeroing, treat *minimum lifetime + no retained reference* as the primary control.

## References
- OWASP ASVS V8.x — Protection of sensitive data in transit, at rest, and in memory
- OWASP WSTG-CRYP-04 — Testing for sensitive information sent via unencrypted / recoverable channels (memory-resident data exposure)
- OWASP Cheat Sheets: Sensitive Data Protection, Password Storage, Cryptographic Storage
