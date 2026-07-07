---
id: P20
name: SessionInvalidation
refs: ASVS V3.3.x, V3.6.x, V8.1.x / WSTG-SESS-06, WSTG-SESS-07 / CS: Session Management, JSON Web Token Cheat Sheet, Logging Cheat Sheet
---

# P20 — Session Invalidation

## Preconditions

The code manages user sessions.


## Overview
Session invalidation flaws arise when a logout, password change, or timeout event does not fully terminate the session **on the server side**. The canonical mistake is treating session termination as a client concern — deleting the cookie or clearing local state — while the underlying session record or token remains valid. Stateless JWTs are the worst offender: by design they cannot be revoked without server-side state, so a "logout" that only removes the token from the browser leaves it usable until natural expiry. The root cause is always a mismatch between what the user believes happened (logged out) and what the server recorded (still authenticated). Attackers who obtain a leaked token (logs, referrer header, XSS, shared machine) continue to act as the victim long after the victim walked away.

## What to check
- Does the logout endpoint destroy the **server-side** session record, not just call `res.clearCookie`? Confirm the store actually deletes/expiry-stamps the row.
- For JWT-based auth, is there a server-side revocation mechanism (denylist, `jti`-keyed revoked-set, versioned `user.token_version`, short-lived access tokens with refresh-token rotation)? A logout that only clears `localStorage`/cookie is a finding.
- Is the session invalidated on **password change/reset**, privilege change, MFA enrollment, and suspected compromise? Old tokens must stop working after these events.
- Does login-on-a-new-device or "logout everywhere" actually revoke other active sessions, or only the current one?
- Are refresh tokens one-time-use and rotated, with reuse detection (rotated-token reuse revokes the whole family)?
- Is there an idle timeout and an absolute max lifetime enforced server-side, or does the session live until the cookie/browser dies?
- Does the app rely solely on cookie expiry (`Max-Age`, `Expires`) or token `exp` claim with no server-side kill switch?
- Are long-lived "remember me" tokens bound to the user and revocable, or random bearer tokens with no server state?
- After logout, does any cached response, SSE/WebSocket connection, or pending `fetch` retain an open authenticated channel?

## Static signals
Logout that touches only the client:
- Node/Express: `app.post('/logout', (req,res) => res.clearCookie('sid').end())` — no `req.session.destroy()`
- `res.clearCookie` / `res.cookie('sid', '', { maxAge: 0 })` without a session-store call
- Django: a custom logout view calling `response.delete_cookie()` instead of `django.contrib.auth.logout(request)`
- Flask: `session.pop('user_id')` / `session.clear()` with server-side `itsdangerous`/DB session row left intact
- Spring Security: `response.addCookie(new Cookie("JSESSIONID",""))` without `SecurityContextHolder.clearContext()` / `request.logout()`

Missing server-side store teardown:
- `req.session.destroy` / `SessionStore.destroy(sid, cb)` absent from the logout path
- Java: `session.invalidate()` missing; only `cookie.setMaxAge(0)`
- Rails: no `reset_session`; cookie cleared manually
- Go (gorilla/sessions): `session.Options.MaxAge = -1` set but `session.Save(r, w)` (which persists) omitted
- PHP: `setcookie('PHPSESSID', '', time()-3600)` without `session_unset()` + `session_destroy()`

JWT without revocation:
- No `jti` denylist / cache lookup; `jwt.verify(token, secret)` is the only check
- Logout handler that does `res.clearCookie('jwt')` or `localStorage.removeItem('token')` with no server record
- Password-change / reset handlers that don't bump a `token_version` (or re-key) used in the verify step
- Refresh-token reuse not detected: missing comparison of presented `jti` against the last-issued one

## False positives
- The app genuinely has server-backed sessions (DB/Redis) and logout destroys the record, plus any JWT is a short-lived (<15 min) access token whose refresh token *is* revoked. Defense-in-depth adequate.
- A pure client-side token is explicitly designed to be stateless, short-TTL (<5 min), used only for non-sensitive reads, with refresh-token rotation enforcing real revocation — acceptable when documented.
- "Remember me" long-lived cookies are opaque server-random IDs indexed in a revocable DB table, not self-contained bearer tokens.
- The framework performs full invalidation internally (Spring `LogoutSuccessHandler` calling `request.logout()`; Django's `logout()` clearing the session) — confirm it actually runs rather than just clearing the cookie.
- Session timeout is enforced by a server middleware that rejects expired records; do not flag merely because the cookie also has a `Max-Age`.

## Attack scenario
1. Victim logs in on a shared/library machine or over a network where the JWT can be observed (TLS-stripping proxy, malicious corporate box, reflected in an error log via `Referer`).
2. Attacker captures the access/refresh JWT. Victim clicks "Logout".
3. The logout handler runs `res.clearCookie('jwt')` (or the SPA does `localStorage.removeItem`) but the server records nothing.
4. The captured JWT is still valid until `exp` (access token: 15 min; refresh token: 30 days).
5. Attacker replays the refresh token to mint fresh access tokens and continues to act as the victim — reading mail, approving transfers, changing the password to lock the victim out — for weeks despite the victim having "logged out".

## Impact
- **Confidentiality**: persistent read access to the victim's account post-logout; full data exfiltration.
- **Integrity**: actions taken as the victim (transfers, config changes, MFA enrollment, password change → account takeover) with no audit trail pointing at logout.
- **Availability**: attacker changes password/mFA and locks the legitimate user out.
- Severity scales with token lifetime and privilege: a 30-day refresh token on an admin account is **High/Critical**; a 5-minute stateless access token with revoked refresh is **Low**. Without server-side revocation the bug is unfixable by the user — only expiry limits the window.

## Remediation
Invalidate server-side state on logout (and on password change, MFA change, and "logout everywhere"):
```ts
// VULNERABLE — cookie clear only; server-side session/JWT still valid
app.post('/logout', (req, res) => {
  res.clearCookie('sid').json({ ok: true });        // session row never deleted
});

// SAFE — destroy server record, deny JWT, clear cookie
app.post('/logout', async (req, res) => {
  const sid = req.sessionID;
  await sessionStore.destroy(sid);                  // tear down opaque session
  await revokedJti.set(req.user.jti, true, 'EX ' + req.user.exp); // denylist JWT jti
  req.session.destroy(() => {
    res.clearCookie('sid', { httpOnly: true, secure: true, sameSite: 'lax' });
    res.json({ ok: true });
  });
});
```
For JWTs, prefer **short-lived access tokens (≤15 min) + rotated, one-time-use refresh tokens with reuse detection**, or a `user.token_version` bumped on logout/password-change and checked at verify time. Never ship a long-lived stateless token with no revocation path. Defense-in-depth: log logout events with `jti`/session-id for forensics, and offer an explicit "revoke all sessions" that bumps the token version globally.

## References
- OWASP ASVS V3.3.x — Session timeout and termination; V3.6.x — token-based session re-authentication; V8.1.x — logging of session lifecycle events
- OWASP WSTG-SESS-06 — Testing for Logout Functionality; WSTG-SESS-07 — Testing Session Timeout
- OWASP Cheat Sheets: Session Management, JSON Web Token Cheat Sheet, Logging Cheat Sheet
