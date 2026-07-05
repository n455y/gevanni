---
id: P62
name: AuditTrail
refs: ASVS V7.x / WSTG-ATHN-08, WSTG-ATHZ-06 / CS: Logging, Application Logging Vocabulary
requires: []
---

# P62 — Audit Trail

## Overview
An audit trail is the tamper-evident, structured record of security-relevant events — authentication successes and failures, authorization denials, password and credential changes, privilege/role changes, and high-risk actions (delete, export, fund transfer, configuration change). When it is missing, incomplete, or unprotected, an attacker can act without leaving evidence, hide their tracks after a breach, and operators cannot reconstruct an incident or prove non-repudiation. The root cause is usually one of three: only the "happy path" is logged (success recorded, failures/lockouts not); audit events omit one of the four required fields (actor / timestamp / target / result); or logs are stored append-only without integrity protection, so they can be edited or truncated by anyone who gains the host.

## What to check
- Are **both** authentication success and failure (including account lockout / rate-limit trips) recorded? A common defect logs only successes, so brute-force and credential-stuffing become invisible.
- Are authorization denials recorded — every `403`, "permission denied", or access-control check that returns negative?
- Are credential lifecycle events logged: password change/reset, MFA enable/disable, API key issuance/revocation, OAuth grant/refresh?
- Are privilege changes logged: role grant/revoke, group membership change, account elevation to admin, step-up authentication for high-risk operations?
- Does every audit event contain **who** (actor: authenticated user id, not just the submitted username on a failed login), **when** (trusted server clock, ISO-8601, monotonic), **what** (target object/resource + action), and **result** (success / fail / deny)?
- Is the actor recorded as a stable internal identifier, and is the source IP / request id / session id captured for correlation?
- Do high-risk operations (delete, bulk export, config change, money movement) emit an audit event *before and after* the action, including the old and new state?
- Are logs append-only / write-once, with integrity protection (WORM storage, hash chaining, or external log shipping) so an attacker who compromises the host cannot rewrite history?
- Are the logs shipped off the host (SIEM, central log server) in near-real-time, so local deletion doesn't destroy the trail?
- Are sensitive data fields redacted (passwords, tokens, full PAN) so the audit log doesn't itself become a data-store of secrets?

## Static signals
Failure to record on the negative path:
- Node: `if (user) { logger.info('login ok'); } req.login(...)` with **no** `else` / `logger.warn('login fail')`
- Python: `except AuthError: pass` or `except PermissionDenied: return redirect(...)` with no audit call
- Java/Spring: a custom `AccessDeniedHandler` / `AuthenticationFailureHandler` that returns 403 without calling an audit logger
- Go: `http.Error(w, "forbidden", 403)` directly with no `audit.Log(...)` around it

Audit event missing required fields (only `event`/`msg`, no actor/time/target/result):
- `logger.info('login success')`
- `logger.info('user updated')`
- `print('permission denied')`
- `log.info("role changed")`

Actor taken from the *submitted* credential on a failed login (wrong) vs the resolved target id, or actor omitted entirely:
- `audit({ event: 'login_fail', user: req.body.email })` (ok if that's the only thing known) but `audit({ event: 'role_change' })` with no actor on an authenticated action
- No `request.user` / `req.user` / `SecurityContextHolder` / `ctx.user` referenced in the audit call

No integrity / tamper protection around the log sink:
- `fs.appendFileSync('audit.log', line)` to a plain file with no hash-chaining or external forwarder
- PHP `error_log($msg, 3, '/var/log/app.log')` to a writable file
- Ruby `File.open('log/audit.log', 'a')` plain append
- Log stored on the same DB table/columns the application can `UPDATE`/`DELETE`

High-risk handlers with no audit emit (grep for the action then check surroundings):
- Routes named `delete`, `remove`, `destroy`, `export`, `download`, `transfer`, `grant`, `revoke`, `reset`, `impersonate` whose handler body has no `audit`/`log`/`event` call

## False positives
- The application uses a framework-managed audit subsystem (Spring Boot Actuator/Audit, Django auth signals connected to a logger, Rails `ActiveSupport::Notifications`, OWASP AppSensor) wired to the relevant hooks, and events include actor/time/target/result — confirm coverage of failures, not just successes.
- High-risk operations go through a central service/gateway that emits the audit event for all callers; individual handlers legitimately have no logging.
- Logs are forwarded to an external SIEM (Splunk, ELK, CloudWatch/LGTM, GCP Logging) with immutable retention and access controls — local append is then acceptable.
- Step-up authentication is enforced for high-risk operations and the step-up event itself is audited.
- In a stateless internal microservice, audit is intentionally delegated to the API gateway / edge; confirm the edge actually logs.

## Attack scenario
1. Attacker launches a credential-stuffing attack against `/login`. Because the app only logs successful logins, the 50,000 failed attempts leave no trace and no lockout/alert fires.
2. The attacker finds one valid credential and logs in. With audit capturing only "login success" and no source IP or target user id, the single legitimate-looking entry blends in.
3. The attacker escalates: they abuse an IDOR/privilege flaw to grant their account admin rights. The role-change handler has no audit call, so the privilege grant is invisible.
4. They export the full customer database. The export endpoint logs only "download" with no actor or record count.
5. After exfiltration, the attacker — who has gained shell on the host — truncates `/var/log/audit.log` and the DB-backed `audit_events` table (which the app can `DELETE`), destroying all evidence.
6. During incident response, the team finds a near-empty audit log, no correlation between events, and no way to scope which accounts or records were affected.

## Impact
- **Confidentiality**: an attack proceeds without detection; sensitive actions (data export, account takeover) are never surfaced.
- **Integrity**: a missing or unprotected trail allows an attacker (or malicious insider) to alter records undetected and breaks non-repudiation — disputed transactions cannot be adjudicated.
- **Availability**: deletion or flooding of the audit log can blind monitoring and incident response, and (if logs share app storage) can fill the disk.
- Severity scales with what the trail is supposed to protect: in finance, healthcare, or compliance-regulated systems a deficient audit trail is a direct regulatory violation (PCI DSS, HIPAA, SOX, GDPR accountability) on top of the underlying compromise.

## Remediation
Centralize all security events through one audit service that enforces the required fields and append-only storage:
```ts
// VULNERABLE — only the success path is logged; fields missing; log is a plain mutable file
app.post('/login', (req, res) => {
  const user = authenticate(req.body.email, req.body.password);
  if (user) { fs.appendFileSync('audit.log', 'login success\n'); req.session.user = user; }
  // failure path: no log at all
  res.json({ ok: !!user });
});

// SAFE — success and failure audited with actor/time/target/result; forwarded off-host
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body.email, req.body.password);
  await audit.emit({
    event:  user ? 'authn_success' : 'authn_failure',
    actor:  user ? user.id : req.body.email, // submitted id is all we have on failure
    target: 'session',
    result: user ? 'success' : 'fail',
    ip:     req.ip,
    rid:    req.id,
    ts:     new Date().toISOString(),
  });
  if (user) req.session.user = user.id;
  res.status(user ? 200 : 401).json({ ok: !!user });
});
```
Defense-in-depth: ship logs to an external, append-only SIEM in near-real-time (so host compromise cannot erase them); hash-chain or WORM-store the local trail; redact secrets (passwords, tokens, full card numbers) at the audit boundary so the log is not itself a data breach; and feed authn_failure spikes into an alerting rule.

## References
- OWASP ASVS V7.1.x, V7.2.x — Logging, audit trails, and protection of logs
- OWASP WSTG-ATHN-08 — Testing for weak or absent logging of authentication events
- OWASP WSTG-ATHZ-06 — Testing for authorization logging / non-repudiation
- OWASP Cheat Sheets: Logging, Application Logging Vocabulary
