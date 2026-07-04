---
id: P13
name: PasswordReset
area: V6 Authentication
refs: ASVS V2.5.x / WSTG-ATHN-09, WSTG-ATHN-10 / CS: Forgot Password, Credential Stuffing Prevention
---

# P13 — Password Reset

## Overview
Password reset (and "forgot password") flows are a primary vector for account takeover because they must bootstrap authentication from an unauthenticated state using only an out-of-band channel (usually email). The design is full of footguns: the reset token must be **cryptographically random and unguessable**, short-lived, single-use, and bound to a single account; the endpoint must not **enumerate** which addresses are registered; and a successful reset must **invalidate all existing sessions** for the user. The root cause of most reset flaws is using a weak PRNG (`Math.random`, timestamps, sequential IDs, truncated hashes) to mint the token, or leaking user existence through differential responses. A predictable or reusable token is equivalent to a credential.

## What to check
- Is the reset token generated with a **CSPRNG** (`crypto.randomBytes`, `secrets.token_urlsafe`, `SecureRandom`, `crypto/rand`)? Any use of `Math.random`, `java.util.Random`, `time()`, sequential counters, or a truncated/truncated-then-hex'd hash is a finding.
- Is the token at least **112–128 bits** of entropy (≥16 bytes raw, ideally 32)?
- Is there an **expiry** (≤15–20 min recommended; ASVS allows up to 1 h)? Long-lived or never-expiring tokens are a finding.
- Is the token **single-use**? Verify a `used` flag / consumption step that rejects replay, and that a token is invalidated on first use, on re-request, and on password change.
- Does the endpoint return an **identical response** whether the email exists or not ("If that address is registered, a link has been sent"), with identical timing, to prevent **account enumeration**?
- Is the reset link served **only over TLS**, bound to the authenticated reset step (token verified server-side before the new password is accepted), and not logged server-side or leaked into `Referer` via embedded trackers/images in the reset email?
- After a successful reset, are **all existing sessions / "remember me" tokens / refresh tokens** for that user revoked?
- Does the flow require **re-authentication or the current password** before changing the password in the authenticated settings page (defending a hijacked active session)?
- Is the new password validated against the **breached-password policy** and complexity rules before being accepted?
- Are tokens stored **hashed** at rest (like passwords), not in plaintext, in the database?

## Static signals
Weak token generation:
- `Math.random()`, `new Date().getTime()`, `Date.now()`, `System.currentTimeMillis()`, `time()`, `microtime()`, `uniqid()`, `rand()`, `mt_rand()` feeding into a token.
- `java.util.Random`, `java.util.concurrent.ThreadLocalRandom` for security tokens.
- `require('uuid/uuid').v1(...)` (time-based UUID — predictable) vs `v4()` with a CSPRNG.
- `md5(email)`, `sha1(userId + secret)`, `substr(hash, 0, 8)` as tokens.
- Go: `math/rand`, `fmt.Sprintf("%d", rand.Int())` instead of `crypto/rand`.

No expiry / long expiry / reusable:
- `ResetToken.create({ userId, token })` with **no** `expiresAt` / `expires_at` column.
- `expiresAt = Date.now() + 24*60*60*1000` (>1 h, or "never").
- Missing `used` / `consumed_at` guard; `WHERE token = ?` without checking `used = false` or `expires_at > now`.

Enumeration leaks (differential response):
- `if (!user) return res.status(404).send('No such account');`
- `if (!user) return res.render('reset', { error: 'Email not registered' });`
- Different flash messages, redirects, or response times for known vs unknown addresses.
- `throw new Error('User not found')` surfacing to the client.

Session-not-revoked after reset:
- `await user.setPassword(newPassword)` with no `Session.destroy(...)`, no `req.logout()` / `token.revoke()`, no `UPDATE refresh_tokens SET revoked`.
- Login flows issuing new sessions without invalidating prior ones.

Plaintext token storage / logging:
- `console.log('reset link', resetUrl)`, `logger.info(token)`, tokens in query logs / error reports.
- `INSERT INTO reset_tokens (token, ...) VALUES (?)` storing the raw token instead of `sha256(token)`.

## False positives
- Token is minted with `crypto.randomBytes(32)` / `secrets.token_urlsafe(32)` / `SecureRandom.getInstanceStrong()` / Go `crypto/rand`, has an `expiresAt ≤ 1 h`, a `used` flag, and is stored hashed — full protection in place.
- Expiry is intentionally slightly longer (e.g. 30–60 min) to absorb email delivery latency and the response is enum-neutral — rate this Medium, not High.
- The "email sent" response is genuinely identical for all inputs (same body, same timing, rate-limited), so enumeration is not exploitable.
- Token is consumed by a host that clicks the link server-side (e.g. SSO back-channel) and never exposed to the browser — confirm binding before dismissing.
- The flow is a **magic-link / passwordless** login, not a password reset — those are covered under P-adjacent auth perspectives but the same token rules apply.

## Attack scenario
1. Attacker targets a known account (e.g. `victim@example.com`) and requests a reset.
2. The token is `Date.now()`-derived or a short hex of an incrementing counter — attacker brute-forces or predicts the value space (a few thousand to a few million candidates).
3. Alternatively, the endpoint reveals `victim@example.com` is registered (unique error message), enabling **credential stuffing / phishing** tailored to that account.
4. Attacker submits the predicted/guessed token to the reset confirmation endpoint before the legitimate user, sets a new password, and takes over the account.
5. Because existing sessions are not invalidated, the attacker also inherits any active "remember me" / refresh tokens — the victim cannot reclaim the account by simply logging out.
6. Variant: attacker reuses an **already-consumed token** to reset the password again after the victim recovers it.

## Impact
- **Confidentiality**: full account takeover — the attacker reads all victim data bound to that account.
- **Integrity**: attacker changes the email/password/MFA, performs transactions, and locks out the true owner.
- **Availability**: account lockout, data destruction, or subscription abuse; if the token is shared across accounts, mass takeover.
- Severity scales from **Medium** (enumeration only) to **Critical** (predictable/reusable token on a high-privilege admin account). Reset-token forgery is generally treated as **High** because it bypasses all authentication guarantees.

## Remediation
```ts
// VULNERABLE — predictable, no expiry, reusable, enum leak
app.post('/reset', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(404).send('No account with that email');
  const token = String(Date.now());                       // predictable
  await ResetToken.create({ userId: user.id, token });    // no expiry, no single-use
  mail(user.email, `https://app/reset?token=${token}`);
});

// SAFE — CSPRNG, short-lived, single-use, hashed at rest, enum-neutral, session revoke
import crypto from 'crypto';

app.post('/reset', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  // identical response + timing regardless of existence
  if (user) {
    const token = crypto.randomBytes(32).toString('hex');         // 256-bit CSPRNG
    const hash  = crypto.createHash('sha256').update(token).digest('hex');
    await ResetToken.create({
      userId: user.id,
      tokenHash: hash,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000),           // 15 min
      used: false,
    });
    mail(user.email, `https://app/reset?token=${token}`);         // not logged server-side
  }
  res.send('If that email is registered, a reset link has been sent.');
});

app.post('/reset/confirm', async (req, res) => {
  const hash = crypto.createHash('sha256').update(req.body.token).digest('hex');
  const rec = await ResetToken.findOne({ tokenHash: hash, used: false });
  if (!rec || rec.expiresAt < Date.now()) return res.status(400).send('Invalid or expired');
  await User.setPassword(rec.userId, req.body.newPassword);       // breaches/complexity checked
  rec.used = true; await rec.save();                              // single-use
  await Session.destroy({ where: { userId: rec.userId } });       // revoke all sessions
  res.send('Password updated');
});
```
Defense-in-depth: bind reset to a short-lived signed state cookie, send the link token out-of-band only, rate-limit the request and confirm endpoints by IP and email, and reject tokens after a small number of failed confirm attempts.

## References
- OWASP ASVS V2.5.x — Credential lifecycle, password reset and recovery
- OWASP WSTG-ATHN-09 — Testing for weak password change/reset
- OWASP WSTG-ATHN-10 — Testing for weak security question / account enumeration
- OWASP Cheat Sheets: Forgot Password, Credential Stuffing Prevention, Password Storage
