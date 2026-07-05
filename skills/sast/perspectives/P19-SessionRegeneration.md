---
id: P19
name: SessionRegeneration
refs: ASVS V3.4.x, V3.7.x / WSTG-SESS-03, WSTG-SESS-08 / CS: Session Management
requires: [backend]
---

# P19 — Session Regeneration

## Overview
Session fixation is a class of attack where the attacker forces a known session ID onto a victim (via a link `?sid=...`, a subdomain cookie, or a pre-set cookie) and then waits for the victim to authenticate. If the application reuses the **same** session identifier after login, the attacker's known ID is now an authenticated session — full account takeover without ever stealing a credential. The defense is to **rotate the session ID on every privilege transition**: at authentication success, at privilege change (e.g. user→admin, anonymous→2FA-verified), at re-authentication, and on logout. The root cause is always the same: a session container is created before authentication and its identifier is not invalidated/replaced when the trust level changes.

## What to check
- On successful authentication (password, SSO, OAuth callback, MFA completion), does the code call the framework's session-rotation API rather than just stamping the user ID into the existing session?
- Is the **old** session ID invalidated server-side (not merely replaced client-side)? A new cookie name alone is not enough if the server still honors the old ID.
- Are session IDs accepted from URL/query/path (`?sid=`, `;jsessionid=`) or request body — enabling fixation via a link? (Cookies only, and `HttpOnly`+`Secure`+`SameSite`.)
- Is `session.use_strict_mode` (PHP) / always-`regenerate` behavior enforced, so an unknown/attacker-supplied SID is never adopted pre-login?
- Does privilege escalation (role change, enabling 2FA, password reset, account merge) trigger a fresh rotation, not just a flag flip?
- On logout, is the session destroyed server-side (`destroy()` / `logout()`) and the cookie expired, not merely cleared on the client?
- Does the session store reject session ID reuse across the rotation boundary (no orphaned old ID still valid)?
- For stateless JWT-only designs: are tokens rotated/re-issued on login and added to a server-side revocation list, or is this genuinely out of scope?

## Static signals
Missing rotation on login (the core smell — old SID retained):
- Node/Express: `req.session.user = ...` / `req.session.userId = ...` with **no** `req.session.regenerate(...)` (callback or `util.promisify`) on the same path.
- Node/Koa: `ctx.session.user = ...` with no `ctx.session` regeneration / `ctx.cookies.set` rotation.
- Python/Django: `login(request, user)` is fine (auto-rotates), but `request.session[...] = user.id` set manually with **no** `request.session.cycle_key()` is suspicious.
- Python/Flask: `session['user_id'] = ...` with no `session_regenerate`-equivalent; Flask does **not** auto-rotate on login.
- Java/Servlet: `request.changeSessionId()` (Servlet 3.1+) is absent after `login()` or manual auth; legacy `request.getSession()` reuse pre/post login.
- Java/Spring Security: `sessionManagement().sessionFixation(...)` left at default for older versions, or explicitly `none()` / `.migrateSession()` disabled.
- Go (gorilla/sessions): `session.Values["uid"] = id` with no `session.Options.MaxAge` reset / ID rotation.
- Ruby/Rails: `session[:user_id] = ...` with no `reset_session` + `session[:user_id]=` pair on login (Rails does not auto-rotate).
- PHP: `$_SESSION['user'] = ...` after login with **no** `session_regenerate_id(true)` (the `true` deletes the old file).

Session ID accepted from non-cookie sources:
- `req.query.sid` / `req.query.session` / `req.params.sid` used as session key.
- Java: `jsessionid` appended to URLs (`response.encodeURL` / `encodeUrl`) — URL-based session tracking enabled.
- PHP: `session.use_only_cookies=0`, `session.use_trans_sid=1`.
- Python: custom `request.args.get('session')` lookup bypassing the session middleware.

Logout without server-side destruction:
- `res.clearCookie('session')` alone (client-side only); no `req.session.destroy()`.
- Rails: `session[:user_id] = nil` instead of `reset_session`.
- PHP: unsetting `$_SESSION` keys without `session_destroy()` + `setcookie(..., time()-1)`.

## False positives
- **Django**: `django.contrib.auth.login()` calls `cycle_key()` internally on Python/Django — manual `cycle_key()` is redundant (not a finding).
- **Spring Security** with default config (Servlet 3.1+ container) applies `changeSessionId()` on authentication automatically; only flag if `sessionFixation().none()` or migration is explicitly disabled.
- **Passport (Node)** itself does *not* regenerate; the application code still must. But some bespoke middleware wrappers add it — confirm before reporting.
- Stateless JWT architectures with no server-side session store (token = self-contained, rotated per login, short-lived) are out of scope — there is no fixatable server session.
- Pre-authenticated (anonymous) session that is destroyed and never authenticated is not a fixation vector.
- Read-only/public endpoints that never elevate privilege.

## Attack scenario
1. Attacker obtains a fresh, unauthenticated session ID `S=abc123` (visits the site, or is handed one via `https://app.example.com/?sid=abc123` because the app reads the SID from the query string).
2. Attacker forces that same ID onto the victim — a link `https://app.example.com/login?sid=abc123`, a crafted QR code, an auto-submitting form, or a subdomain cookie injection if `Domain=.example.com`.
3. Victim's browser now presents `S=abc123`; victim logs in with valid credentials.
4. The login handler does `req.session.user = victim.id` **without** `regenerate()`, so the authenticated session keeps ID `abc123`.
5. Attacker presents `S=abc123` to the server and is now operating inside the victim's authenticated, privileged session — full account takeover, no credential theft required.

## Impact
- **Confidentiality**: complete impersonation of the victim; access to all data and features their account holds.
- **Integrity**: attacker can submit forms, change settings/email/password, authorize transactions as the victim.
- **Availability**: account lockout, password change, or data destruction in the victim's name.
- Severity scales with the victim's privileges — fixation on an admin login path becomes full application compromise. Often rated High/Critical because it bypasses authentication entirely rather than breaking it.

## Remediation
Rotate the session identifier at every privilege transition, and destroy the old one server-side:
```ts
// VULNERABLE — session fixation: old SID retained after login
app.post('/login', (req, res) => {
  if (checkCredentials(req.body)) {
    req.session.user = user.id;        // same session ID, now authenticated
    res.redirect('/dashboard');
  }
});

// SAFE — rotate on login, then stamp identity into the fresh session
app.post('/login', async (req, res) => {
  const user = await checkCredentials(req.body);
  if (!user) return res.status(401).send('invalid');
  await new Promise<void>((resolve, reject) =>
    req.session.regenerate(err => (err ? reject(err) : resolve()))
  );
  req.session.user = user.id;
  res.redirect('/dashboard');
});
```
Accept session IDs **only** from cookies (`HttpOnly`, `Secure`, `SameSite=Lax/Strict`); enable `session.use_strict_mode` (PHP) / never honor an unknown pre-auth SID. As defense-in-depth, also rotate on logout (`req.session.destroy()`), on privilege escalation, and on password change/reset.

## References
- OWASP ASVS V3.4.x (session timeout/rotation), V3.7.x (session fixation / regeneration) — Session Management
- OWASP WSTG-SESS-03 — Testing for Session Fixation; WSTG-SESS-08 — Testing for Session Puzzling / fixation variants
- OWASP Cheat Sheet: Session Management
