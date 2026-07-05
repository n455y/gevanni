---
id: P11
name: MFA
refs: ASVS V2.1.x, V2.2.x / WSTG-ATHN-08, WSTG-ATHN-09 / CS: Multifactor Authentication, Forgot Password, Choosing and Using Security Questions
requires: [backend]
---

# P11 — MFA

## Overview
Multi-Factor Authentication (MFA) is a primary control against credential compromise, yet it is frequently implemented in a way that can be bypassed at the application layer. The core weakness is rarely the second factor itself (TOTP, WebAuthn, SMS) but the **orchestration around it**: the server failing to enforce the second step before issuing a fully privileged session, allowing client-side flags to skip it, leaking the shared secret into a tamperable token, or omitting rate limiting on the verification endpoint. When MFA is bypassable, the attacker needs only the (commonly leaked or phished) password to take over the account, so the entire second factor becomes dead weight. Worse, organizations relying on "MFA enabled" for compliance may not notice the gap until a breach.

## What to check
- Is the **second factor enforced server-side** before any authenticated session/state is granted? Watch for flows where a valid password immediately issues a full session cookie, with MFA treated as an optional screen the client navigates to.
- Can the MFA step be skipped via a client-controllable flag — request body field (`skipMfa`, `trustDevice`), query parameter (`?mfa=bypass`), or a header that the server trusts to short-circuit verification?
- Is the "remember this device" / trusted-device feature secure? The trust marker must be an unforgeable, server-issued, rotated token — not a plain boolean cookie the client can set to `true`.
- Where is the TOTP/WebAuthn secret stored? It must never be embedded client-side or placed in a JWT/cookie readable by the user. Confirm it is encrypted at rest in the credential store.
- Is the MFA **code-verification endpoint rate-limited and lockout-protected**? A 6-digit TOTP code has only 1,000,000 values; without throttling, it is brute-forceable in minutes.
- Is the same code reusable until expiry (no replay protection / one-time-use check)?
- Does the password-check endpoint leak whether MFA is enrolled, or reveal the user's second-factor channel (SMS number) via a response difference (user enumeration)?
- For SMS/email-OTP: is the OTP sufficiently random, short-lived, and bound to the specific transaction? SMS is susceptible to SIM-swap/interception; treat it as lower assurance.
- After a correct MFA submission, does the server re-verify the password step (step-up) or issue the session, and is the MFA-cleared state recorded server-side (not in a client-asserted claim)?
- Are recovery codes generated with a CSPRNG, hashed at rest, one-time-use, and rate-limited on use?

## Static signals
Client-controllable bypass of the second factor:
- `if (req.body.skipMfa) return issueSession(user);`
- `if (req.body.rememberDevice === 'true') { res.cookie('mfa_verified','1'); ... }`
- `if (req.query.step === 'skip' || user.role === 'admin') bypassMfa()`
- `res.cookie('mfa', 'done');` set without server verification, then trusted downstream

Second-factor verification done client-side only:
- Frontend calls the normal login API, gets a full session, then optionally prompts for TOTP without the server gating on it.
- `if (await verifyTotp(secret, code)) localStorage.setItem('mfa', '1');` — gate is purely UI.

Secret/credential exposed to the client:
- TOTP secret returned in a login/refresh response, or placed in a JWT: `jwt.sign({ uid, totpSecret }, key)`
- QR provisioning URI emitted more than once, or without first requiring an authenticated session.
- WebAuthn credential ID / backup codes sent to the browser unhashed.

No throttling on the verification endpoint:
- `app.post('/verify-otp', ...)` with no `rateLimit`, no `express-slow-down`, no failed-attempt counter.
- Django/Flask view accepting OTP with no `@ratelimit` decorator or lockout table.

Replay / reuse not prevented:
- Verification compares code only, never records `last_used_code` / `last_used_counter` (HOTP) — TOTP RFC 6238 explicitly mandates rejecting reused codes within the time window.

Weak recovery / SMS-OTP:
- Recovery codes from `Math.random()` / `random.randint()` instead of a CSPRNG; stored in plaintext.
- SMS code is 4 digits, valid for 10+ minutes, no lockout.

## False positives
- Risk-based (adaptive) MFA that requires the second factor only for elevated-risk operations (new device, sensitive action) — this is a legitimate, ASVS-aligned design pattern when the default sessions are still scoped low-trust. Flag as Info/Medium, not a bypass.
- WebAuthn / Passkey-based implementations where the second factor is the primary credential — these are strongly resistant to phishing and bypass; this perspective trends toward a positive finding.
- A `trustDevice` flag that is genuinely an unforgeable signed token with finite lifetime and server-side revocation — verify the token, then it is acceptable.
- A flow that issues a *pre-auth* / *pending* cookie after the password (not a session cookie) and only upgrades it after MFA success — this is correct, not a bypass.

## Attack scenario
1. Attacker obtains a victim's password via a separate phishing site or a credential-stuffing list (commonly available).
2. The target site verifies the password and issues a full session, then redirects the browser to an MFA prompt — but the MFA check is enforced only on the client route, not the API.
3. Attacker authenticates directly with the API (curl / their own client), omitting the MFA step, and receives the authenticated session cookie / token.
4. Alternatively, if the verification endpoint lacks rate limiting, the attacker brute-forces the 6-digit TOTP space (~1e6) in a few minutes of automated requests.
5. Either path yields a fully authenticated session without possession of the second factor — full account takeover, plus any privileged actions (payments, admin console, data export).

## Impact
- **Confidentiality**: total account takeover — inbox, personal data, linked services, payment methods.
- **Integrity**: attacker can change settings, authorize transactions, modify records, and reset further credentials while impersonating the victim.
- **Availability**: attacker can lock the victim out (change password/recovery, revoke sessions).
- Severity scales steeply with the victim's privileges: a bypass on an admin or financial account is Critical; on a standard low-value account it remains High because MFA is the advertised protection and its absence is rarely detected.

## Remediation
Enforce the second factor server-side, gate the session on it, and rate-limit verification:
```ts
// VULNERABLE — client flag bypasses the second factor
app.post('/login', async (req, res) => {
  const user = await verifyPassword(req.body);
  if (!user) return res.status(401).end();
  if (req.body.skipMfa) return res.json({ token: signSession(user) }); // bypass
  return res.json({ mfaRequired: true });
});

// SAFE — server-issued pending state, MFA verified before session grant
app.post('/login', async (req, res) => {
  const user = await verifyPassword(req.body);
  if (!user) return res.status(401).end();
  const pending = signPending({ uid: user.id }, { expiresIn: '5m' }); // pre-auth only
  return res.json({ mfaRequired: true, pending });
});

app.post('/verify-otp', otpRateLimit, async (req, res) => {
  const { uid } = verifyPending(req.body.pending);
  const user = await getUser(uid);
  if (!await verifyTotp(user.totpSecret, req.body.code, user.lastUsedCode))
    return res.status(401).end();
  await markCodeUsed(user, req.body.code);            // replay protection
  res.json({ token: signSession(user, { mfa: true }) });
});
```
As defense-in-depth: store TOTP/recovery secrets encrypted at rest, never place them in client-readable tokens, prefer WebAuthn/passkeys over SMS/OTP, and log + alert on repeated MFA failures.

## References
- OWASP ASVS V2.1.x, V2.2.x — Password security, MFA, and credential lifecycle requirements
- OWASP WSTG-ATHN-08 (Testing for MFA), WSTG-ATHN-09 (Testing for weak lock-out)
- OWASP Cheat Sheets: Multifactor Authentication, Forgot Password, Choosing and Using Security Questions
