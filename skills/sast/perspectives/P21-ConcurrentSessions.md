---
id: P21
name: ConcurrentSessions
refs: ASVS V3.3.x / WSTG-SESS-05 / CS: Session Management
---

# P21 — ConcurrentSessions

## Preconditions

The code manages user sessions.


## Overview
Concurrent session control governs how many active sessions a single account may hold at once and how the application reacts when new logins occur. When unbounded, the same credentials can power dozens of simultaneous sessions from disjoint IPs, devices, and geographies — making stolen/leased credentials, account sharing, and session hijacking far harder to detect and contain. The root cause is usually a session store keyed only by session ID with no per-user cap or eviction policy: each login mints a fresh opaque token and the old ones keep working. A robust implementation limits concurrent sessions, surfaces an authenticated "devices / active sessions" list, and lets the user revoke any of them.

## What to check
- Is there a maximum number of concurrent **valid sessions per user** (and per device class)? What happens on the `N+1`-th login — reject, or evict the oldest?
- On a fresh successful login, are the user's **prior sessions** invalidated, capped, or left untouched? (Leaving them all valid is the vulnerable default.)
- Is the session store keyed/indexed by `user_id` (so you can enumerate and revoke per user), or only by session ID?
- Are session tokens tied to a device fingerprint, IP range, or user-agent, with re-validation (or invalidation) on a suspicious change?
- Does the application detect concurrent use from **impossible/improbable locations** (geo-velocity) or many IPs in a short window?
- Is there an authenticated UI listing active sessions (device, location, last-seen, IP) with one-click revoke? Is server-side logout reachable from it?
- On password change / credential reset / MFA enrollment, are all other sessions invalidated?
- Are idle and absolute timeouts set (so abandoned sessions expire even if no cap exists)?
- For stateless JWT auth: is there a revocation list or short expiry + refresh, or are tokens unrevocable until they naturally expire?

## Static signals
Unbounded session creation (no per-user index/cap):
- Node: `sessions.set(sid, { user })` with no `sessionsByUser` map or `MAX_SESSIONS` check
- Express/Passport: `app.post('/login', passport.authenticate(...))` with no `req.sessionStore` pruning
- Python/Django: `Session.objects.create(user=...)` without deleting prior rows; `SESSION_COOKIE_AGE` set but no concurrent limit
- Flask: storing sessions in a dict/Redis by `sid` only, never iterating by `user_id`
- Java/Spring Security: default `SessionManagementConfigurer` with no `.maximumSessions(n)` / `.maxSessionsPreventsLogin(true)`
- Rails: `session[:user_id] = user.id` with Devise but no `config.maximum_concurrent_sessions` / timeoutable strategy that evicts
- Go: `store[sid] = userID` map guarded by a mutex but never filtered by user

Session revocation gaps:
- Logout that only clears the current token: `res.clearCookie('sid')` / `session.destroy()` / `del redis:sid` — but leaves the user's **other** tokens valid
- JWT `Authorization: Bearer` with no server-side denylist; logout is purely client-side (token remains valid until exp)
- Refresh-token rotation that does not revoke the family on reuse

Missing index for per-user enumeration:
- No query/code path like `SELECT * FROM sessions WHERE user_id = ?` or `redis.smembers('user:{id}:sessions')`
- No `/account/devices` or `/sessions` endpoint; no "revoke" route

## False positives
- Multi-device concurrent login is an explicit product requirement (consumer SaaS, streaming shared profiles) — no hard cap is acceptable as a **Low**, but session visibility + revocation should still exist.
- The application already enforces `.maximumSessions(n).maxSessionsPreventsLogin(true)` (Spring Security) or an equivalent cap elsewhere, so unbounded creation is not actually reachable.
- Stateless JWT with very short access-token TTL (e.g. 5 min) + refresh rotation with family reuse detection — concurrent exposure is bounded by the short window.
- Single sign-on / federated IdP where the upstream IdP (Okta, Auth0) owns session concurrency; the app is a passive relying party.

## Attack scenario
1. Attacker acquires valid credentials via phishing, a credential-stuffing list, or a stealer log, but does **not** trigger a login the real user would notice (no forced logout).
2. Because there is no per-user session cap and prior sessions are never invalidated, the attacker's brand-new session coexists indefinitely with the victim's.
3. The attacker operates the account in parallel — reading data, approving transactions, exfiltrating PII — while the victim's own session keeps working, masking the compromise.
4. With no session-list UI or geo/anomaly detection, the victim has no way to see or revoke the rogue session. The compromise persists until tokens naturally expire (which may be never, if absolute timeouts are missing).

## Impact
- **Confidentiality**: undetected long-term read access to the victim's data and messages.
- **Integrity**: parallel attacker-initiated actions (transfers, config changes, privilege grants) attributed to the victim.
- **Availability**: attacker can lock out / exhaust a session cap the user depends on, or change credentials.
- Severity scales with account privilege: a compromised admin with unbounded sessions yields persistent, stealthy full application access.

## Remediation
Cap and index sessions per user; invalidate prior tokens on events that should reset trust:
```ts
// VULNERABLE — new login mints a token, old sessions keep working
sessions.set(sid, { user });

// SAFE — cap concurrent sessions, evict oldest, index by user for revocation
const list = sessionsByUser.get(user.id) ?? [];
while (list.length >= MAX_SESSIONS) {
  const old = list.shift();
  sessions.delete(old);              // revoke oldest
  denylist.add(old);                 // stateless/JWT: deny until exp
}
list.push(sid);
sessionsByUser.set(user.id, list);
sessions.set(sid, { user, ua, ip, createdAt });
```
On password change, MFA enrollment, or user-initiated "logout all," iterate the per-user index and revoke every token. Surface the session list in an authenticated UI and add geo-velocity / new-IP-MFA as defense-in-depth so a stolen credential cannot silently spawn a parallel session.

## References
- OWASP ASVS V3.3.x — Session termination, concurrency, and timeout requirements
- OWASP WSTG-SESS-05 — Testing for Session Puzzling / concurrent session controls
- OWASP Cheat Sheet: Session Management
