---
id: P84
name: LimitBypass
refs: ASVS V11.x / WSTG-BUSL-03 / CS: REST Security
---

# P84 — Limit Bypass

## Preconditions

The code accepts user actions that should be rate-limited or restricted.


## Overview
A limit bypass occurs when a business rule that caps quantity, rate, or frequency — votes per day, transfers per hour, withdrawal attempts, OTP guesses, coupon redemptions, search/export volumes — is enforced only on the client, or enforced server-side in a way an attacker can evade (race condition, key rotation, multi-account, or per-IP-only throttling). The root cause is always that the **trust boundary is in the wrong place**: the server trusts a value it should recompute, or it checks a counter it does not update atomically. Unlike classic injection flaws, the code looks correct at a glance because "the limit is there" — it just doesn't actually bind the attacker, who can repeat the action until they exhaust a resource, drain a balance, swing a vote, or brute-force a credential.

## What to check
- Is there **any** server-side cap on how many times a sensitive action (send, vote, transfer, withdraw, redeem, invite, search, export, login/OTP attempt) can run per identity per window?
- Is the limit enforced **client-side only** — disabled button, JS counter, hidden field, or a "you already did this" flag returned to the browser and trusted on resubmit?
- What is the **key** the limit is keyed on? Per-IP alone falls to a botnet/rotating proxy; per-account alone falls to multi-account/Sybil registration; per-device alone falls to header spoofing. Good designs combine identity + IP + device/behavior.
- Is the counter update **atomic**? A read-then-increment (`count = SELECT ...; if count < N then INSERT`) is racy — concurrent requests all read the same count and pass the gate.
- Can the limit be reset/evaded by changing a parameter — re-issuing an OTP to rotate the attempt counter, switching `transferId`, replaying with a new `couponCode`, or altering `userId`/`deviceId` in the request?
- Are rate-limit headers (`X-RateLimit-*`, `Retry-After`) backed by an enforced server-side store, or are they advisory/decorative?
- Is the limit applied uniformly across channels (web, mobile API, internal admin, GraphQL field)? A common gap is the REST path being throttled while a parallel GraphQL mutation or mobile endpoint is not.
- Does a successful high-value action decrement a quota that is refunded/cancellable client-side (e.g. `?cancel=true` after the side effect already happened)?

## Static signals
No server-side cap on a mutating/sensitive route:
- `app.post('/vote', (req, res) => votes++)` — no `if (count >= LIMIT)` guard
- `@app.route('/transfer', methods=['POST'])` with no `rate_limit` decorator / no quota lookup
- Spring `@PostMapping("/withdraw")` with no `@RateLimit` / no per-user counter

Client-only enforcement (server trusts a client value):
- `if (req.body.alreadyVoted) return 400;` — the flag is attacker-controlled
- `if (req.headers['x-device-id'] !== lastDevice)` — header is trivially changed
- Returning `canVote = false` to the UI and gating only on that response

Non-atomic read-then-write (race window):
- `const n = await Vote.countToday(userId); if (n >= LIMIT) return 429; await Vote.create(...)` — TOCTOU
- `count = redis.get(key); if count > N: deny; redis.incr(key)` — get/incr not pipelined atomically
- Python/Django: `qs = Vote.objects.filter(user=user, date=today); if qs.count() >= LIMIT: return; Vote.objects.create(...)`

Per-IP-only or single-dimension keying:
- `rate_limit_by_ip()` / `@limiter.limit("5/min")` keyed solely on `request.remote_addr`
- Limit keyed on `userId` with no anti-Sybil check at registration

Resettable/evadable counters:
- OTP verification: `attempts` counter scoped to a `txnId` that the user can regenerate by re-requesting a code
- Quota stored in a mutable client cookie / JWT claim: `res.cookie('votesLeft', n)`

Advisory headers with no store:
- `res.set('X-RateLimit-Remaining', String(n))` with no backing increment

## False positives
- The server enforces a composite limit (identity + IP + device fingerprint + behavioral signals) with an **atomic** increment (DB unique constraint, `INCR`+`EXPIRE` in a single Redis pipeline, or a conditional `UPDATE ... WHERE count < N`), and anti-automation (CAPTCHA/step-up auth) on registration to blunt Sybil abuse.
- The action is genuinely idempotent and low-impact (e.g. reading a public profile) where repetition causes no resource drain or integrity change.
- The "limit" is a UX affordance (e.g. "show 20 results per page") that the server clamps regardless of client input, with no business cost to repetition.
- Rate limiting is delegated to a verified edge layer (WAF/API gateway with authenticated, per-token buckets) that the code path is confirmed to traverse.

## Attack scenario
1. The app lets each user transfer 1000 currency units per day. The check is `balance = SELECT ...; if balance >= amount then debit`, with no per-day total counter.
2. Attacker opens 50 concurrent requests, each transferring 1000 to a mule account. All read `balance = 1000` before any debit commits.
3. Every request passes the balance gate; 50,000 units leave the account against a 1000-unit daily intent.
4. Alternatively: the per-user counter exists but uses `count` then `insert`; the attacker fires concurrent identical votes/withdrawals, all reading `count = 9` under a limit of 10, so dozens of actions commit past the cap.
5. If the limit is per-IP only, a rotating-proxy or cellular botnet evades it trivially; if per-account only, the attacker registers N accounts.

## Impact
- **Confidentiality**: mass data export/search scraping beyond intended quota; bulk enumeration of records via repeated "limited" queries.
- **Integrity**: vote/result manipulation, multi-redemption of one-time coupons, double-spending or over-withdrawal, OTP brute-force when attempt caps are evadable — can cascade to account takeover.
- **Availability**: resource exhaustion (SMS/email/queue flooding via repeated "send" actions), cost amplification (cloud egress, paid third-party API calls), and denial of wallet.
- Severity scales with the action: an uncapped transfer or OTP attempt path is typically Critical; an uncapped "favorite" toggle is Low.

## Remediation
Enforce limits server-side, atomically, on a composite key:
```ts
// VULNERABLE — no limit / client-only / non-atomic
app.post('/vote', async (req, res) => {
  const n = await Vote.countToday(req.user.id);      // read
  if (n >= LIMIT) return res.status(429).end();
  await Vote.create({ userId: req.user.id });        // window: many concurrent reqs pass
});

// SAFE — atomic conditional insert + unique constraint + composite keying
app.post('/vote', async (req, res) => {
  const ip = realClientIp(req);                       // behind trusted proxy
  if (await isFlaggedDevice(req.body.deviceId, ip)) return res.status(429).end();
  try {
    // DB unique constraint on (user_id, vote_date) makes the INSERT itself the gate;
    // a conditional UPDATE (... WHERE used < LIMIT RETURNING ...) works for counters.
    await Vote.create({ userId: req.user.id, voteDate: today, ip });
  } catch (e) {                                       // unique violation → over-limit
    if (e.code === '23505') return res.status(429).end();
    throw e;
  }
  res.status(201).end();
});
```
For pure rate limiting prefer an atomic store (Redis `INCR`+`EXPIRE` in one pipeline, or a Lua script) over read-then-write. Defense-in-depth: pair per-identity limits with per-IP and per-device buckets, step-up authentication (MFA/CAPTCHA) when a threshold is approached, and Sybil-resistant registration so the per-account key cannot be inflated at will.

## References
- OWASP ASVS V11.x — Business logic and integrity controls
- OWASP WSTG-BUSL-03 — Testing for process timing / rate-limit and concurrency bypasses
- OWASP Cheat Sheet: REST Security (rate limiting, idempotency)
