---
id: P18
name: SessionTimeout
refs: ASVS V3.3.x / WSTG-SESS-07 / CS: Session Management, Transaction Authorization
requires: [backend]
---

# P18 — SessionTimeout

## Overview
Session timeout is the controlled expiration of an authenticated session after a period of inactivity (idle/absolute) or a hard maximum lifetime. When it is absent, set too long, or silently refreshed on every request without bound, a stolen or abandoned session token remains valid indefinitely — turning a one-time token leak (XSS, log entry, shared device, shoulder-surfing) into persistent account access. The root cause is usually a missing/explicitly-disabled `expiresIn` / `exp` / `maxAge`, an over-generous sliding window with no absolute cap, or a "remember me" path that issues a long-lived primary token instead of a separate low-privilege refresh token.

## What to check
- Is an **idle timeout** (session terminated after N minutes of no activity) configured? ASVS recommends ≤ 15 minutes for high-assurance apps, ≤ 2–4 hours for low-risk.
- Is an **absolute / maximum session lifetime** enforced (hard cap regardless of activity)? A sliding-only timeout lets an active attacker live forever.
- Does the sliding/expiring window get refreshed on **every** request, effectively making the session immortal? Is there a ceiling the renewal cannot exceed?
- For JWT-based sessions: is the `exp` claim present and short? Is `expiresIn` set to days/weeks/years (`'10y'`, `'365d'`) or omitted entirely?
- Is there a server-side revocation/invalidation path, or are stateless JWTs impossible to kill before `exp`?
- Does the app disable cookie expiry (`cookie.expires = false`, `Max-Age` unset, `session.cookie.expires = false`)?
- Is the session store (Redis, DB) purged on timeout, or do stale sessions linger server-side?
- Are high-risk operations (password change, money transfer, admin actions) protected by a separate, shorter **step-up / transaction timeout** rather than the general session?
- Does "remember me" issue a distinct, scoped refresh/long-lived token, or does it just extend the primary session token?

## Static signals
Session/JWT lifetime missing or excessive:
- `jwt.sign(payload, secret)` — no third `options` arg, hence no `expiresIn`
- `jwt.sign(payload, secret, { expiresIn: '10y' })` / `'365d'` / `'1 year'`
- `jsonwebtoken` config: `expiresIn: 0`, missing, or `expiresIn: false`
- Express/`express-session`: `cookie: { expires: false }`, `cookie: { maxAge: null }`, `unset: 'destroy'` absent
- `req.session.cookie.maxAge = Number.MAX_SAFE_INTEGER` or values in the billions of ms

Sliding window with no absolute cap:
- Every request re-runs `req.session.touch()` / `session.save()` / sets `maxAge = 30*60*1000` again — never bounded by an original absolute deadline.
- Spring `server.servlet.session.timeout` with `cookie` refresh but no `max-inactive-interval` ceiling.
- Django `SESSION_COOKIE_AGE` + `SESSION_SAVE_EVERY_REQUEST = True` with no `SESSION_EXPIRE_AT_BROWSER_CLOSE` discipline and no absolute cap.

Stateless JWT not revocable:
- No allow-list / blacklist / version check on the token; `verify()` only checks signature + `exp`.

Other frameworks:
- Python (`flask`): `app.permanent_session_lifetime = timedelta(days=365)`, `PERMANENT_SESSION_LIFETIME` huge.
- Go (`gorilla/sessions`): `Session.Options{MaxAge: 0}` (0 = browser-session in some stores, but a huge value is a smell).
- PHP: `session_set_cookie_params(['lifetime' => 0])` with `session.gc_maxlifetime` enormous; `session.cookie_lifetime = 31536000`.
- Ruby/Rails: `expire_after` omitted from session store config, or set to a multi-day value.
- Java/Spring: `server.servlet.session.timeout=86400` (24h+) with sliding renewal.

## False positives
- A deliberate **"remember me"** flow that issues a *separate* low-privilege, revocable refresh/long-lived token while the primary auth session still has a short absolute timeout — acceptable (verify the refresh token is scoped and revocable).
- The app has an independent **step-up authentication** for sensitive operations, so a long base session is acceptable for read-only browsing.
- The value found is the *refresh-token* lifetime (long by design), not the access/session-token lifetime — confirm which token it governs.
- Native/mobile app with secure local token storage + server-enforced revocation; mobile UX legitimately tolerates longer sessions, though an absolute cap should still exist.
- The huge number is a unit confusion (seconds vs ms) — verify the framework's expected unit before reporting.

## Attack scenario
1. Attacker obtains a victim's session cookie/JWT once (XSS payload, a copy left in a proxy/server log, a shared kiosk, or a stolen laptop).
2. Because `expiresIn` is `'30d'` or the sliding window resets on every request with no absolute cap, the token stays valid for weeks.
3. The attacker reuses the token from their own machine long after the victim stopped using the app — no re-authentication is ever triggered.
4. With no server-side revocation list (stateless JWT), even after the victim notices and "logs out", the old token still works until `exp`.
5. The attacker maintains silent persistent access to the account, exfiltrating data or staging further abuse.

## Impact
- **Confidentiality**: persistent unauthorized access to the victim's data, messages, and history.
- **Integrity**: ongoing ability to perform actions as the victim (transfers, config changes) without re-auth.
- **Availability**: account lockout, destructive actions, or credential changes that lock out the real owner.
- Severity scales with session length and privilege: an immortal admin session converts any one-time token leak into long-term full application compromise.

## Remediation
Enforce both an idle and an absolute timeout; never issue an unbounded or session-only-expiring token:
```ts
// VULNERABLE — no expiry, immortal session
const token = jwt.sign(payload, secret);
app.use(session({ secret, cookie: { expires: false } }));

// SAFE — short idle + bounded absolute lifetime, server-side revocable
const token = jwt.sign(
  { ...payload, iat: now },
  secret,
  { expiresIn: '15m' }              // short-lived access token
);
// server-side session store enforces absolute cap + revocation
app.use(session({
  secret,
  resave: false,
  saveUninitialized: false,
  rolling: true,                    // refresh idle window on activity
  cookie: {
    httpOnly: true, secure: true, sameSite: 'lax',
    maxAge: 15 * 60 * 1000,         // 15-minute idle timeout
  },
}));
// separately, enforce an absolute lifetime cap server-side (e.g. 8h) and revoke on logout.
```
Use a separate, revocable refresh token for "remember me" rather than extending the primary session, and add server-side session invalidation (deny-list or version bump) so compromised tokens can be killed before `exp`. As defense-in-depth, require re-authentication before high-risk transactions regardless of session age.

## References
- OWASP ASVS V3.3.x — Session timeout and termination requirements
- OWASP WSTG-SESS-07 — Testing Session Timeout
- OWASP Cheat Sheets: Session Management, Transaction Authorization
