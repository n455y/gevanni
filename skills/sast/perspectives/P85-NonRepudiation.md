---
id: P85
name: NonRepudiation
area: V2 Validation and Business Logic
refs: ASVS V11.2.x / WSTG-BUSL-05 / CS: Transaction Authorization, Logging
requires: [backend]
---

# P85 — NonRepudiation

## Overview
Non-repudiation is the property that the originator of a high-value action — a payment, an asset transfer, a contract or privilege change — cannot later credibly deny having performed it. It fails when the audit trail for such transactions is absent, incomplete, or forgeable: no record of *who* acted, *when*, on *what* subject, with *what result*, no tamper protection (signature, hash chain, append-only store), and no idempotency control so a replay can silently double-spend. The root cause is treating a state-mutating business operation like any other CRUD write, trusting client-supplied timestamps/identifiers, and recording only success/failure rather than a cryptographically attributable event. Without an immutable, actor-bound ledger, dispute resolution and regulator inquiries collapse into "he said / she said."

## What to check
- Does every high-value transaction (payment, transfer, order fulfillment, credential/permission grant, contract amendment) produce an audit record capturing **actor identity, server timestamp, target object, before/after state, result, and request signature/trace id**?
- Is the timestamp derived from a trusted server clock (NTP-synced), **not** from a client-supplied value (`Date.now()` echoed by the browser, a `timestamp`/`ts` request field)?
- Is there an **idempotency key** (e.g. `Idempotency-Key` header) bound to the actor so that a network retry, double-click, or replay produces exactly one effect and one audit entry?
- Are audit records tamper-evident — hash-chained, signed, written to an append-only/immutable store (WORM, blockchain, or an append-only table with restricted grants), or streamed to an external SIEM that the application cannot rewrite?
- Does the record tie to a strong, authenticated identity (verified session, step-up auth, or a user signature), not an ambiguous "system" actor or a shared service account?
- For financial flows, is the durable record created **before/at** the mutation within the same transaction (commit audit + effect atomically), so a crash cannot leave an effect with no record or a record with no effect?
- Is the originating request itself logged or signed (e.g. JWS, detached signature over the canonicalized payload) so a later claim of "I never sent that" can be refuted?

## Static signals
Missing audit / actor attribution on mutating calls:
- Node: `await Payment.create(req.body)`, `db.transfer.update(...)`, `Order.delete(...)` with no surrounding `audit.log(...)` / `AuditTrail.create(...)`
- Python: `Payment.objects.create(**data)`, `session.commit()` with no `audit_event(...)` call in the same transaction
- Java: repository `.save(entity)` with no `AuditService.record(...)` aspect or `@Audited` annotation
- Go: `db.Create(&tx)` with no `AppendAudit(...)` in the same `Tx`

Trusting client-controlled time or identity:
- `const ts = req.body.timestamp` / `req.body.ts` / `req.headers['x-client-time']` used as the event time
- `audit.t = request.json['timestamp']` (Python/Flask), `body.get("ts")` (Java/Spring)
- Using `req.headers['x-user-id']` or `req.body.userId` as the actor instead of the authenticated principal (`req.user.id`, `ctx.state.user`)

No idempotency guard on financial/submit endpoints:
- `app.post('/pay', (req,res) => charge(req.body))` — no `Idempotency-Key` lookup / dedupe table
- Python: `@app.post("/pay") def pay(...): charge(...)` with no `@idempotent` decorator / redis SETNX on a key
- Java: `@PostMapping("/pay")` method with no `@Idempotent`/dedupe check
- Go: handler calls `Charge()` directly with no `IfAbsent` insert keyed by idempotency header

Tamper-prone storage (mutable/updatable audit):
- Audit records stored in the same updatable table as business data; an `UPDATE audit_log SET ...` or `db.Audit.Update(...)` path exists
- `repo.save(auditEvent)` (JPA) where the entity is not immutable; Go `db.Model(&Audit{}).Updates(...)`
- No hash-chain / signature field on the audit row (`prevHash`, `sig`), and no append-only constraint

## False positives
- The endpoint is read-only or low-value (list, search, profile view) — audit is good practice but non-repudiation is not in scope.
- The application delegates non-repudiation to an external, trusted system: a payment gateway that returns its own signed receipt, a managed ledger, or a SIEM that ingests immutable records over a write-only channel.
- An idempotency layer is implemented indirectly — e.g. a database unique constraint on `(account_id, external_ref)` that rejects duplicate submissions, or an event-sourcing store keyed by a client request id.
- The "audit" is intentionally minimal because a fuller immutable record is kept downstream (e.g. all DB writes land on a PITR/append-only WAL or CDC stream that the app cannot alter).
- Step-up auth / 2FA / signed challenge at transaction time provides attribution even if the audit row itself is lightweight.

## Attack scenario
1. A customer initiates a wire transfer; the network drops the response, so the mobile app automatically retries.
2. The backend lacks an idempotency key, so the retry executes `transfer()` a second time and the recipient is paid twice.
3. The endpoint writes only `status=completed` to the orders table; there is no actor/timestamp/trace audit row and no signature.
4. When the customer disputes the duplicate charge, the operator cannot prove *who* triggered the second call, *when* it arrived, or whether it was a genuine retry vs. an internal error — the record is absent or forgeable.
5. Separately, because the timestamp is taken from `req.body.ts`, an attacker (or a tampered client) can back-date or forward-date events, undermining any timeline reconstruction and enabling repudiation ("that transaction was not mine").

## Impact
- **Integrity**: duplicate/replayed transactions, unauthorized state changes, disputed contracts and transfers with no reliable record.
- **Confidentiality**: secondary — incomplete logs can hide data-exfiltrating actions; over-broad logs can leak PII if not protected.
- **Availability**: replay storms (no idempotency) can exhaust capacity or drain accounts; dispute lockups freeze business flows.
- Severity scales with transaction value and regulatory exposure: a payment or securities-transfer flow lacking non-repudiation is typically High/Critical; a low-value preference update is negligible.

## Remediation
Make the audit record, idempotency check, and business mutation atomic, and use a server clock plus a signed/append-only trail:
```ts
// VULNERABLE — no idempotency, no audit, trusts client timestamp
app.post('/transfer', async (req, res) => {
  const result = await transfer(req.body);                 // retries double-spend
  res.json(result);                                          // nothing recorded
});

// SAFE — idempotency key, server time, append-only signed audit in one tx
app.post('/transfer', async (req, res) => {
  const tx = await db.transaction(async (t) => {
    // exactly one effect across retries, keyed by client idempotency header + actor
    const effect = await runIfNew(
      t, `idem:${req.user.id}:${req.headers['idempotency-key']}`,
      () => transfer(req.body, { actor: req.user.id, t }),
    );
    // immutable, attributed, tamper-evident record committed atomically
    await Audit.create({
      event: 'transfer', actor: req.user.id, target: effect.id,
      before: effect.before, after: effect.after,
      ts: Date.now(),                      // SERVER clock, not req.body.ts
      sig: sign(effect),                   // hash-chain or detached signature
    }, { transaction: t });
    return effect;
  });
  res.json(tx);
});
```
As defense-in-depth, stream audit events to a write-only external SIEM/append-only store the application cannot update, require step-up authentication for high-value actions, and periodically verify the hash chain/signature integrity of the audit log.

## References
- OWASP ASVS V11.2.x — Business Logic / transaction integrity and audit logging
- OWASP WSTG-BUSL-05 — Testing for Non-Repudiation / Tamper-Resistant Audit
- OWASP Cheat Sheets: Transaction Authorization, Logging, Web Application Logging
