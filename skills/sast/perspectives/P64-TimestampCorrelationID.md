---
id: P64
name: TimestampCorrelationID
refs: ASVS V7.x / WSTG-INFO-02, WSTG-ATHZ-06 / CS: Logging, Distributed Tracing
---

# P64 — TimestampCorrelationID

## Preconditions

The code writes logs.


## Overview
Audit logs, security events, and transaction records are only as trustworthy as the **timestamps and correlation IDs** attached to them. When an application stamps a record with client-supplied time (`req.body.timestamp`), an unsynchronized local clock, or an unparseable/free-form string, the resulting log can be forged, skewed, or rendered unusable for forensic reconstruction and incident response. Likewise, when each service hop emits independent log lines with no propagated `traceId`/`correlationId`, a multi-step attack that crosses service boundaries becomes impossible to follow end-to-end. The root causes are uniformly: trusting user-controlled input for time, relying on a single unverified local clock, and omitting distributed-tracing correlation. The fix is to stamp server-side with a synchronized, monotonic clock, reject or ignore client-provided time, and propagate a request-scoped correlation ID across every hop.

## What to check
- Is any audit/security log entry stamped with a value originating from the request (`req.body.timestamp`, `req.headers['x-timestamp']`, a JWT `iat`/`exp` claim, a signed-cookie time) instead of the server clock at log time?
- Is the server clock synchronized to a reliable source (NTP / cloud metadata clock / `ClockBound`)? Is time read monotonically (e.g. `Instant.now()`, `time.Now()`) rather than recomputed from wall-clock arithmetic that can drift or jump backward across DST/NTP corrections?
- Are timestamps stored in a single canonical, sortable, UTC format (ISO-8601 with explicit offset / RFC3339 / Unix epoch milliseconds) rather than locale-dependent strings, ambiguous regional formats, or user-preferred display values persisted to the store?
- Does every request receive a server-generated correlation/trace ID (and is it regenerated rather than trusted when supplied by the client) that is propagated to downstream calls, log lines, and responses?
- Is the correlation ID logged on **every** log line across **every** service hop (gateway → API → worker → DB/external call) so an attack can be reconstructed end-to-end?
- For tamper-evidence requirements (compliance, billing, legal hold), is there a signed timestamp (RFC 3161 TSA, hash-chained/append-only log like AWS CloudTrail, or HMAC over log batches)? Plain append-only files can be silently edited by anyone with disk access.
- Are log records written synchronously/buffered-flushed before the protected operation completes, so a crash mid-transaction does not lose the audit trail?
- Does the application distinguish `iat`/`exp`/`nbf` (token validity windows, which are inputs to *validate*) from event timestamps (which must be stamped server-side at occurrence)?

## Static signals
Client-supplied time used as the audit/event timestamp:
- `audit({ ts: req.body.timestamp, ... })` / `log({ time: req.headers['x-time'] })`
- `event.time = data.get('timestamp')` (Python) — request body driving the stored time
- Java: `audit.setTime(request.getParameter("ts"))` / `new Date(req.getHeader("X-Event-Time"))`
- Go: `e := Event{Time: parseTime(r.Header.Get("X-Ts"))}`
- Ruby: `Audit.create!(at: params[:event_time], ...)`
- PHP: `$log->time = $_POST['timestamp'];`
- Trusting a JWT claim as the record time: `log({ ts: jwt.iat })` — `iat` is an issuer assertion, not proof of when *this* event happened.

Local clock only, no synchronization / monotonicity / immutability:
- `new Date().toString()` stored without offset, or `toLocaleString()` persisted to the store (locale-dependent, ambiguous).
- Wall-clock arithmetic: `expires = new Date(Date.now() + ttl*1000)` recomputed from drifting `now` rather than a monotonic deadline.
- Time read in a way that can jump backward: Go `time.Now()` is monotonic-qualified (safe), but Java `System.currentTimeMillis()` is not — compare against `Instant.now()`.

Missing correlation ID:
- No `req.id` / `traceId` / `X-Request-Id` in the log record; downstream `fetch`/`http`/`grpc`/`axios` calls do not forward it.
- `req.headers['x-request-id']` is **trusted and reused** rather than regenerated/validated — an attacker can forge a benign-looking ID to mask a malicious flow or collide with another user's trace to poison log correlation.
- Logging framework configured without a MDC/context field (no `winston`/`pino` `requestId`, no SLF4J MDC, no `context.Context` value, no Lograge `request_id`).

Unsortable / unparseable stored time:
- String concatenation: `ts = day + "/" + month + "/" + year` (ambiguous DD/MM vs MM/DD).
- Free-form text persisted where a query must later sort/filter by time.

## False positives
- The server stamps time itself with a synchronized clock (`Instant.now()`, NTP-synced), stores it in UTC ISO-8601, and propagates a server-generated correlation ID across hops — fully protected.
- RFC 3161 signed timestamps or hash-chained/append-only log shipping (CloudTrail,tamper-evident WORM storage) is in place for tamper-sensitive audit trails.
- Client-supplied time is accepted only as **input data** (e.g. scheduling a future event) and validated against server time bounds, never used as the *record's* own `created_at`/`logged_at`.
- A correlation ID from a trusted upstream gateway is propagated verbatim (still acceptable) — but it should be regenerated or validated if it crosses a trust boundary (the public internet).
- The endpoint is an internal/worker pipeline with its own job ID serving as the correlation key, and tracing within that job is consistent.

## Attack scenario
1. Attacker submits a sensitive action (e.g. privileged config change, fund transfer) with `{"timestamp": "2020-01-01T00:00:00Z"}` in the body.
2. The handler logs the action using `req.body.timestamp` as the audit time, and the record lands in the audit trail with a stale, attacker-chosen timestamp.
3. During an incident review, the forged record either (a) appears to predate the attacker's access window — creating reasonable doubt about attribution — or (b) is dropped by a time-windowed SIEM query, hiding it from detection entirely.
4. Separately, because no `traceId` is propagated, the cross-service hop (API → worker → external payout) logs each step under a different request context; the three lines cannot be linked, and the full transaction is untraceable.
5. Combined with an unsynchronized clock that can jump backward, even legitimately stamped events may overlap or invert, undermining the integrity of the entire log as forensic evidence.

## Impact
- **Integrity**: forged timestamps let an attacker retime, hide, or misattribute actions — destroying the evidentiary value of audit logs and defeating after-the-fact investigation.
- **Confidentiality**: trace-linkage gaps mean a credential-leak or data-exfil chain spread across services cannot be correlated, allowing a breach to go undetected or be mis-scoped.
- **Availability**: in time-gated controls (TTLs, rate limits, replay windows), a skewed or backward-jumping clock can drop legitimate traffic (false expiry) or keep expired tokens/sessions alive past their window.
- Severity scales with what the logs protect: billing, compliance (PCI/SOC2/GDPR), non-repudiation, and legal-hold records all collapse if the timestamp can be forged or the trace cannot be reconstructed.

## Remediation
Stamp time server-side with a synchronized clock, store in UTC ISO-8601, and propagate a server-generated correlation ID — never trust client-supplied time for the record's own timestamp:
```ts
// VULNERABLE — client-supplied time drives the audit record
function auditEvent(req) {
  return db.insert('audit', {
    ts: req.body.timestamp,          // attacker-controlled
    action: 'config.change',
    // no traceId — untraceable across services
  });
}

// SAFE — server clock + canonical format + server-generated correlation ID
function auditEvent(req) {
  return db.insert('audit', {
    ts: new Date().toISOString(),    // server time, UTC ISO-8601
    action: 'config.change',
    traceId: req.id,                 // regenerated server-side, propagated to every downstream call
    actorId: req.user.id,
  });
}
```
Also: synchronize hosts to NTP/cloud clock, prefer monotonic time sources for deadlines/replay windows, and for tamper-sensitive trails add RFC 3161 signed timestamps or ship to append-only/hash-chained storage (e.g. CloudTrail) as defense-in-depth — so a forged record cannot be silently inserted or edited.

## References
- OWASP ASVS V7.x — Logging, monitoring, and data protection (audit log integrity, correlation)
- OWASP WSTG-INFO-02 (fingerprint / time skew), WSTG-ATHZ-06 — testing time/authorization-related weaknesses
- OWASP Cheat Sheets: Logging, Distributed Tracing
- IETF RFC 3161 — Internet X.509 PKI Time-Stamp Protocol (signed timestamps for tamper-evidence)
