---
id: P6
name: PasswordStrength
refs: ASVS V2.5.x / WSTG-ATHN-07 / CS: Password Storage, Authentication Cheat Sheet
requires: [backend]
---

# P6 — PasswordStrength

## Overview
Weak password policy is a foundational authentication flaw: it lets users choose credentials that are trivially guessed or cracked offline from a leaked hash. The root cause is almost always a policy that is enforced **client-side only** (and thus bypassable), that sets a minimum length too small (sub-8, let alone the NIST-recommended ≥8 with ≥12 encouraged), that omits a breach/weak-password list check, or that imposes obsolete complexity rules (mandatory symbols/mixed-case) which NIST SP 800-63B explicitly discourages in favor of length and breach-list screening. Also frequently missing: a sane **maximum length** (to prevent truncation-driven false matches and DoS on expensive hashers). The net effect is that password entropy is left to chance, making every other control (rate limiting, hashing, MFA) work harder than it needs to.

## What to check
- Is there a **server-side** minimum length check, and is it ≥8 (ideally ≥12 or ≥15)? Any client-only check (HTML `minlength`, zod on the client, JS validator) is bypassable and effectively absent.
- Is the password screened against a **breached-password / common-password list** (e.g. HIBP Pwned Passwords API, a bundled top-N list)? NIST 800-63B §5.1.1.2 mandates this.
- Are **composition rules** (must contain digit/symbol/upper) absent? Per NIST they should NOT be required; length + breach-list is the modern baseline. If they ARE required, flag as a smell, not a vuln.
- Is a **maximum length** enforced (e.g. 64–1024 chars)? Without it, bcrypt/truncation issues arise (bcrypt silently truncates at 72 bytes) and very long passwords can be used for CPU-DoS on slow hashes.
- Is the password rejected when it **equals the username, email, or display name**, or contains them as substrings?
- Are credentials changed by the user after a reset/breach, not reused from a known-compromised pool?
- Does registration, password-change, AND password-reset endpoints all enforce the same policy? Reset flows are the classic gap.
- Is the password strength check performed **before** hashing/storing, and before any expensive verification?
- Is no length/complexity policy enforced on **generated/temporary** passwords that are intended to be rotated? (Temp passwords should be high-entropy random, not policy-validated human strings — different concern.)
- Are error messages neutral so they don't confirm whether an account exists (vs. "password too weak")?

## Static signals
Client-side-only validation (bypassable — high-signal):
- HTML attributes: `minlength="6"` (or no `minlength`), `pattern="..."`, `required` on `<input type="password">` with no server counterpart
- Front-end-only zod/yup/joi: `password: z.string().min(6)` imported into a `*.client.*` / React component / browser bundle, never re-run server-side
- `bcrypt.hash(password)` with no preceding length/breach check

No server-side minimum length / sub-8 minimum:
- Node: `z.string().min(6)`, `joi.string().min(6)`, `password.length < 6`
- Python: `if len(password) < 6:`, `min_length=6` on a DRF serializer / django field, `validators=[MinLengthValidator(6)]`
- Java: `password.length() < 6`, Bean Validation `@Size(min = 6)`
- Go: `if len(pw) < 6 {`, `validate:"min=6"`
- PHP: `strlen($pw) < 6`, Laravel `'password' => 'min:6'`
- Ruby: `password.length < 6`, Rails `validates :password, length: { minimum: 6 }`

No breach-list / weak-list screening (look for the ABSENCE of these):
- No call to HIBP / `pwnedpasswords` / `zxcvbn` / `passlib` / a denylist
- No constant-time comparison against a top-N list (grep for `common_passwords`, `rockyou`, `weaklist`, `blacklist`)

Truncation / max-length hazards:
- bcrypt used with **no pre-truncation guard**: `bcrypt.hash(pw, 10)` — passwords >72 bytes collide silently (no `if pw.length > 72` rejection)
- DB column `password VARCHAR(72)` or hash stored truncated
- No `maxLength` on the input at all → unbounded input to a slow KDF

Reset-flow gap:
- Password-reset handler / "set new password" endpoint has a different (or missing) validation path than `/register` — e.g. `app.post('/reset', ...)` without the zod schema applied

Composition over length (NIST-discouraged):
- Regex like `/^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/` enforced while `min(6)` is allowed

## False positives
- **Passwordless model**: the system authenticates only via OAuth/SSO, Passkeys/WebAuthn, or magic links and stores no password at all → not applicable. Confirm there's genuinely no password column/flow.
- **Server-side validator already strong**: Django `AUTH_PASSWORD_VALIDATORS` includes `MinimumLengthValidator(min_length=12)` and a `CommonPasswordValidator`; zod schema is invoked in the route handler (not just the client) and includes a breach `.refine()`; ASP.NET Core Identity `PasswordOptions` set to length ≥12. These are protected — verify the validator actually runs on the server path.
- **Temporary/generated passwords**: one-time high-entropy tokens sent for first-login reset are not human passwords and don't need a strength policy (they need expiry + rotation).
- **Internal/admin-only system** with enforced SSO + no local passwords — same as passwordless.
- **Hashing library handles length**: argon2/scrypt/PBKDF2 don't truncate, so a missing bcrypt-style 72-byte guard is only a real risk under bcrypt/PBKDF2 truncation; flag accordingly, don't over-report.

## Attack scenario
1. The registration endpoint validates password length only via an HTML `minlength="6"` and a client-side zod schema. An attacker bypasses both with a direct `curl`/Burp request.
2. Victim selects a common password (`Password1`, `qwerty123`) that passes the trivial 6-char floor and has no breach-list screening.
3. Attacker obtains a leaked credential dump for the app (SQLi, third-party breach reuse) or just runs a credential-stuffing list of top-1000 passwords.
4. Because the hash is weak and the password is in every cracking wordlist, the attacker cracks it offline in seconds, OR simply logs in by stuffing (`qwerty123` works against many accounts).
5. Attacker operates as the victim — reads mail, authorizes transactions, escalates if the victim is staff. Since the policy was the root weakness, the same password reused across many users yields mass compromise.

## Impact
- **Confidentiality**: full account compromise; theft of any data the account can see.
- **Integrity**: attacker performs actions as the user (change email/2FA, approve transfers, post as the user).
- **Availability**: account lockout abuse, or deletion/defacement of the user's content.
- Severity scales with the victim's role (a reused weak admin password = application-wide takeover) and with how many users share common passwords (mass account takeover via a single leaked list). When combined with weak hashing (P7), offline cracking makes this critical.

## Remediation
Enforce length + breach-list on the server, for every credential-setting path:
```ts
// VULNERABLE — client-only, no server policy
app.post('/register', (req, res) =>
  db.createUser({ email: req.body.email, password: hash(req.body.password) }));

// SAFE — server-side length + breach list + ban username reuse
const RegisterSchema = z.object({
  email: z.string().email(),
  password: z.string()
    .min(8)                              // ASVS V2.5.1 minimum; encourage ≥12
    .max(1024)                           // cap for slow-hash DoS / truncation safety
    .refine(p => !p.toLowerCase().includes(req.body.email.split('@')[0].toLowerCase()),
            'must not contain your username')
    .refine(notInBreachedList, 'password appears in known breaches'), // HIBP / bundled list
});

app.post('/register', async (req, res) => {
  const { email, password } = RegisterSchema.parse(req.body);
  // If using bcrypt, reject >72-byte passwords BEFORE hashing (bcrypt truncates)
  if (password.length > 72) return res.status(400).json({ error: 'password too long' });
  await db.createUser({ email, password: await bcrypt.hash(password, 12) });
});
```
Drop mandatory complexity rules (NIST 800-63B §5.1.1.1); rely on length + breach screening. As defense-in-depth, offer a meter (`zxcvbn`) on the client to guide users, rate-limit login, and pair the policy with a strong slow hash (argon2id preferred over bcrypt — see P7) so that any weak password that does slip through is still expensive to crack offline.

## References
- OWASP ASVS V2.5.x — Credential storage and password policy requirements (V2.5.1 min length, V2.5.2 breached-password screening, V2.5.3 max length)
- OWASP WSTG-ATHN-07 — Testing for Weak Password Policy
- OWASP Cheat Sheets: Password Storage, Authentication
- NIST SP 800-63B §5.1.1 — Memorized Secret Verifiers (length, no composition rules, breach-list check)
