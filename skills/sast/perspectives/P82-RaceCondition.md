---
id: P82
name: RaceCondition
area: V2 Validation and Business Logic
refs: ASVS V11.1.x, V4.x / WSTG-BUSL-06, WSTG-ATHZ-06 / CS: Race Conditions, Transaction Authorization
requires: [backend]
---

# P82 — RaceCondition

## Overview
A race condition (TOCTOU — time-of-check to time-of-use) occurs when a multi-step operation that should be atomic — read a value, validate a business rule, then mutate state — is instead split across separate non-locked steps, leaving a window in which concurrent requests observe stale state. The root cause is a missing transaction boundary, missing row lock, or missing conditional/atomic update. Classic victims are wallet balances, inventory counts, coupon/redemption limits, rate counters, withdrawal caps, and one-time-use tokens. Because web handlers run in parallel threads/instances, an attacker firing N simultaneous requests can each pass the check before any of them commits the update, yielding double-spending, stock oversell, or repeated application of a single-use action.

## What to check
- Is there a **read → check → update** sequence on shared mutable state (balance, stock, counter, coupon-used flag) that is not wrapped in a single transaction?
- Does the check rely on a value read into memory/application code rather than enforced inside the database (`UPDATE ... SET x = x - n WHERE x >= n`)?
- Is a unique constraint missing on idempotency keys (e.g. `(user_id, coupon_code)`), so duplicate redemptions are possible?
- Are one-time operations (password reset, email verification, withdrawal, vote, MFA disable) gated by a flag that is read-then-set rather than atomically claimed (`UPDATE ... WHERE status = 'unused' RETURNING`)?
- Are limits (withdrawal/day, attempts, free-tier calls) incremented by read-modify-write in a cache (Redis `GET`/`SET`) instead of atomic ops (`INCR`, Lua script)?
- Are file-system or shared-resource checks (temp-file `exists()` then `open()`, mkdir-p) non-atomic (symlink attack / TOCTOU)?
- In distributed deployments, is a distributed lock / advisory lock used where the same key spans multiple DB connections or nodes?

## Static signals
Read-modify-write without a transaction or conditional update:
- Node/Prisma: `const u = await Wallet.findFirst(uid); if (u.balance >= amt) await Wallet.update({ balance: u.balance - amt })`
- Sequelize: `Wallet.findOne(id)` → `if (...) Wallet.debit()` (read-then-write)
- Python/Django: `u = Wallet.objects.get(id); if u.balance >= amt: u.balance -= amt; u.save()` (lost update)
- Python/SQLAlchemy: `wallet.balance -= amt; db.commit()` without `with_for_update()`
- Rails: `w = Wallet.find(id); if w.balance >= amt; w.update(balance: w.balance - amt)` — same pattern
- Go/GORM: `db.First(&w, id); if w.Balance >= amt { w.Balance -= amt; db.Save(&w) }`
- Java/JPA: `Wallet w = repo.findById(id); if (w.getBalance() >= amt) w.setBalance(...) ; repo.save(w)` — no `@Lock(PESSIMISTIC_WRITE)`

Atomic primitives done right (signals of *safe* code — absence is the smell):
- SQL: `UPDATE wallets SET balance = balance - :amt WHERE id = :id AND balance >= :amt` and checking affected-row count
- Prisma: `updateMany({ where: { id, balance: { gte: amt } }, data: { balance: { decrement: amt } } })` then check `count === 1`
- Django: `Wallet.objects.filter(id=id, balance__gte=amt).update(balance=F('balance') - amt)`
- SQLAlchemy: `query.filter(Wallet.id == id, Wallet.balance >= amt).update({Wallet.balance: Wallet.balance - amt})`
- Rails: `Wallet.where(id: id).where('balance >= ?', amt).update_all('balance = balance - ?', amt)`
- Redis: `INCR`, `INCRBY`, or a Lua script / `WATCH`/`MULTI` for multi-key updates
- Java: `synchronized`/`ReentrantLock` only valid single-process; DB `SELECT ... FOR UPDATE` for cross-connection

Idempotency-key gaps:
- One-time token consumed by `token = Token.find(); if (!token.used) { token.used = true; token.save() }` (no unique constraint, no conditional update)
- File TOCTOU: `if !fs.existsSync(p) fs.writeFileSync(p)` (Node), `if not os.path.exists(p): open(p)` (Python)

## False positives
- The update is a single conditional `UPDATE ... WHERE` on the protected invariant and the code checks the affected-row count — the DB serializes it.
- The critical section is inside a transaction with row-level lock (`SELECT ... FOR UPDATE`) and the invariant is re-checked after locking.
- A correctly-implemented distributed lock (Redlock with fencing tokens, Postgres advisory lock, etcd lease) guards the multi-step flow.
- A unique constraint plus an idempotency key (`INSERT ... ON CONFLICT DO NOTHING`) makes duplicate submissions impossible.
- The value is per-request state (not shared across requests) — no concurrency, no race.
- Read-only access with no subsequent mutation based on the read.

## Attack scenario
1. The withdrawal endpoint reads the wallet balance, checks `balance >= amount`, then debits — three steps, no transaction.
2. Attacker has a balance of 100 and sends 10 concurrent `POST /withdraw` requests each for `amount=100`, using `curl`/Turbo Intruder with a gating `X1: pause` header held open until all connections are established, then released simultaneously.
3. All 10 requests read `balance = 100` before any debit commits; all 10 pass the `>= 100` check.
4. Each request debits 100 from a wallet that only ever held 100 — net result: balance goes negative (e.g. -900) or, if clamped at 0, the attacker extracted far more than their balance.
5. Same primitive defeats coupon-once-per-user, limited-quantity sales, vote-brigading, and "first N sign-ups" promotions.

## Impact
- **Confidentiality**: usually low direct impact, but balance/count tampering can expose others' state in dependent reports.
- **Integrity**: HIGH — money/credits duplicated, stock oversold, single-use coupons/tokens reused, limits (withdrawal/day, rate limits) bypassed. Integrity is the primary concern.
- **Availability**: oversold inventory, exhausted quota pools, or negative-balance integrity errors can break order/cleanup pipelines.
- Severity scales with the value of the asset being double-spent and whether the race is trivially repeatable (single burst) vs. requires tight timing; modern load-balanced multi-instance apps make almost any TOCTOU exploitable.

## Remediation
Push the invariant check into the database as an atomic, conditional update and act on the affected-row count:
```ts
// VULNERABLE — read, check, then separate update (race window)
const u = await Wallet.findById(uid);
if (u.balance >= amt) {
  await Wallet.update(uid, { balance: u.balance - amt });
  await payout(amt);
}

// SAFE — single atomic conditional update; check rows affected
const n = await Wallet.updateMany({
  where: { id: uid, balance: { gte: amt } },
  data: { balance: { decrement: amt } },
});
if (n.count === 0) throw new Error('insufficient funds');
await payout(amt);
```
For multi-table flows, wrap in a serializable transaction with `SELECT ... FOR UPDATE` on the gating row, and add a unique constraint on an idempotency key (`(user_id, coupon_code)`) so duplicate submissions are rejected by the DB rather than by application logic. Defense-in-depth: pair the atomic update with idempotency keys passed by the client so retries can't double-spend even if a connection drops mid-flight.

## References
- OWASP ASVS V11.1.x — Business Logic Security; V4.x — Access Control / transaction authorization
- OWASP WSTG-BUSL-06 — Testing for Race Conditions; WSTG-ATHZ-06 — Testing for Authorization bypass via TOCTOU
- OWASP Cheat Sheets: Race Conditions, Transaction Authorization
