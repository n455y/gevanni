---
id: P31
name: AuthzTOCTOU
refs: ASVS V4.x / WSTG-ATHZ-06 / CS: Authorization, Race Conditions
---

# P31 — AuthzTOCTOU

## Preconditions

The code checks authorization before performing actions.


## Overview
A Time-Of-Check-to-Time-Of-Use (TOCTOU) authorization flaw exists when the authorization decision and the state-changing operation it guards are **not executed atomically**. Between the check (e.g. "does the user have enough balance / quota?") and the use (the actual decrement, transfer, or state mutation), a second concurrent request can slip through and pass the same now-stale check — letting one privileged precondition authorize many simultaneous operations. The root cause is a read-modify-write sequence performed without a transaction, row lock, or a single conditional `UPDATE`. Classic manifestations are double-spending of balances/coupons/withdrawals, bypass of rate limits and one-time-use tokens, and IDOR-style access where the ownership check races against an ownership transfer.

## What to check
- Is any authorization predicate (balance, quota, stock, coupon redemption count, "owns resource?", "already used?") evaluated in a separate query from the mutation it authorizes, with no transaction or lock spanning both?
- Are decrement/increment operations written as **two steps** (`SELECT balance` → `if balance >= amt` → `UPDATE balance = balance - amt`) instead of a single conditional `UPDATE ... WHERE balance >= amt`?
- Are one-time-use resources (password-reset tokens, OAuth codes, voting ballots, referral bonuses, gift cards) validated and invalidated in two steps without a unique constraint or `UPDATE ... WHERE used = false`?
- Does the app rely on an in-memory check (cache, session counter, Redis `GET` then `SET`) without an atomic primitive (`WATCH`/`MULTI`, Lua script, `INCR`, `SETNX`, Redlock)?
- Are file-system authorization checks (`access()` then `open()`) or symlink-laden paths used — classic Unix TOCTOU on `/tmp`?
- Does the ownership check re-read the resource inside the same transaction that mutates it, or does it trust a stale ORM object fetched earlier (pre-`save`)?
- Are long-running "hold then commit" flows (reservation → payment) vulnerable to the resource being re-bound or revoked mid-flow?

## Static signals
Non-atomic read → check → write (the core smell):
- Node: `const bal = await getBalance(uid); if (bal >= amt) await charge(uid, amt);`
- Node (Sequelize): two calls instead of conditional update — `user.balance -= amt; await user.save();` after a separate `findByPk`
- Python/Django: `bal = Account.objects.get(id=uid).balance; if bal >= amt: a.balance -= amt; a.save()`
- Python/SQLAlchemy: `acct = session.query(Account).get(uid); if acct.balance >= amt: acct.balance -= amt`
- Ruby/Rails: `bal = account.balance; if bal >= amt then account.update(balance: bal - amt) end`
- Go: `var bal int; db.Get(&bal, ...); if bal >= amt { db.Exec("UPDATE ... SET balance = ?", bal - amt) }`
- PHP/Laravel: `$bal = $account->balance; if ($bal >= $amt) { $account->balance -= $amt; $account->save(); }`
- Java/JPA: `if (account.getBalance().compareTo(amt) >= 0) { account.setBalance(account.getBalance().subtract(amt)); em.persist(account); }` without `@Version`/optimistic lock or `SELECT ... FOR UPDATE`

Two-step one-time-use without unique constraint:
- `if (!Token.used) { Token.used = true; await Token.save(); }`  (race redeems the token twice)
- `SELECT * FROM votes WHERE user_id=? AND poll_id=?` then `INSERT INTO votes`

In-memory counters / Redis without atomicity:
- `const n = await redis.get(key); if (n < LIMIT) await redis.incr(key);`  (should be `INCR` then check the returned value, or Lua)

File-system TOCTOU:
- C: `access(path, R_OK)` ... `open(path)`  (symlink swap between calls)
- Node: `fs.exists` / `fs.stat` then `fs.readFile` on attacker-influenced `/tmp` paths

Missing transaction boundaries:
- `@transactional` absent, or `REPEATABLE READ`/`SERIALIZABLE` isolation not used where a phantom read defeats the check
- No `SELECT ... FOR UPDATE` (row lock) before the conditional write
- ORM optimistic-locking column (`@Version` / `lock_version`) not declared on the entity being mutated

## False positives
- The mutation is a single conditional `UPDATE ... SET balance = balance - ? WHERE id = ? AND balance >= ?` and the app checks the affected-rows count — atomic and safe.
- The whole check-and-mutate runs inside one DB transaction with `SELECT ... FOR UPDATE` (pessimistic) or an enforced `@Version`/`lock_version` (optimistic) that aborts on stale read.
- A Redis/Lua atomic primitive (`INCR`, `SETNX`, `MULTI`/`EXEC` with `WATCH`, a single `EVAL` script) makes the increment-and-throttle atomic.
- The protected resource is genuinely read-only for the attacker (state never changes between check and use) — downgrade to Low.
- A unique DB constraint (`UNIQUE(user_id, poll_id)`, `UNIQUE(token)`) makes double-use impossible at the storage layer even if the application logic races.

## Attack scenario
1. Attacker holds an account with a 100-unit balance and initiates a 100-unit withdrawal — authorized exactly once.
2. Instead of one request, the attacker fires N concurrent identical withdrawal requests against the non-atomic endpoint.
3. Every worker thread runs `SELECT balance` (sees 100 ≥ 100, passes the check) before any worker reaches the `UPDATE`.
4. All N requests pass the authorization check against the same stale balance and each issues a `charge`/`UPDATE`.
5. The attacker receives N × 100 units while the balance only went negative (or hit a floor), turning a single permitted withdrawal into a multiplied payout. The same pattern redeems a one-time coupon hundreds of times or casts duplicate votes.

## Impact
- **Confidentiality**: secondary — race-induced IDOR can expose a resource briefly reassigned to the attacker.
- **Integrity**: the primary loss — double-spending, duplicated votes/referrals/bonuses, bypass of rate limits and one-time-token semantics, fraudulent transfers.
- **Availability**: quota exhaustion / lock contention can also degrade service for other users.
- Severity scales with the value of the raced resource: a coupon double-spend may be Low/Medium; a withdrawal/transfer race or an admin-grant race is Critical. Exploitability is high (parallel HTTP requests need no special privileges).

## Remediation
Make check-and-use a single atomic operation; never split read, decide, and write:
```ts
// VULNERABLE — read → check → update race window
const bal = await getBalance(uid);
if (bal >= amt) await charge(uid, amt);

// SAFE — single conditional UPDATE, decide by affected-rows
const [updated] = await Account.update(
  { balance: sequelize.literal('balance - :amt') },
  { where: { id: uid, balance: { [Op.gte]: amt } }, replacements: { amt } }
);
if (updated === 0) throw new AuthError('insufficient funds');
```
For one-time-use tokens, enforce a `UNIQUE`/`used` flag in the same conditional `UPDATE ... WHERE used = false` and check the affected-rows count; for in-memory limits use an atomic Redis `INCR`/Lua script. Wrap multi-statement flows in a transaction with `SELECT ... FOR UPDATE` or an ORM optimistic-lock (`@Version`/`lock_version`) column, and never trust an ORM object fetched before the transaction began. Defense-in-depth: add server-side idempotency keys so a replayed client request cannot double-apply a state change.

## References
- OWASP ASVS V4.x — Access Control (race-safe authorization), V11.x — Business Logic
- OWASP WSTG-ATHZ-06 — Testing for Time-of-Check-to-Time-Use (TOCTOU) / race conditions
- OWASP Cheat Sheets: Authorization, Race Conditions
