---
id: P83
name: CouponReuse
refs: ASVS V11.x / WSTG-BUSL-03, WSTG-BUSL-04 / CS: REST Security
requires: [backend]
---

# P83 — CouponReuse

## Overview
Coupon / promotion / referral-code abuse is a business-logic flaw where the server validates only whether a code is *valid* but fails to enforce *who* may use it, *how many times*, *within what window*, or *against what minimum spend*. Unlike injection or XSS there is no malformed payload — the attacker simply replays a legitimate code in a way the developer never intended (infinite reuse, stacking, application to an empty cart, race-condition claiming). The root cause is missing server-side state: redemption counts, per-user bindings, expiry, and minimum-cart guards are checked partially or not at all, and the redemption is not made atomic against concurrent requests.

## What to check
- Is redemption tracked per `(user, coupon)`? A code limited to "one per customer" must be enforced by a unique constraint or transactional insert, not by a `SELECT ... WHERE used = false` followed by an independent `UPDATE`.
- Is the **global** usage cap (e.g. first 1000 redemptions) decremented atomically with `UPDATE ... SET used = used + 1 WHERE used < limit` and a row-count check, not a read-then-write that loses under concurrency?
- Is the expiry (`valid_from` / `valid_until`) validated server-side against server time, never client-supplied timestamps?
- Is a minimum-cart / minimum-item / category restriction enforced *after* the cart is finalized, so an attacker cannot apply the coupon to an empty or 1-cent cart and bank the discount?
- Are negative, fractional, or absurdly large discount values rejected? A `-100%` or `999999` discount must never be accepted from the client.
- Can multiple coupons be stacked onto one order in violation of business rules? Is stacking validated server-side?
- Are referral / invite codes bound to the inviter and limited to N referrals, with self-referral prevented?
- Does the order-cancellation / refund flow *reverse* the coupon redemption so the same code can't be reused across cancelled orders?
- Is rate limiting applied to the coupon-apply endpoint to slow brute-forcing of codes?

## Static signals
Validity-only check, no usage / ownership / expiry tracking:
- `if (await Coupon.findOne({ code: req.body.code })) applyDiscount()` (Node/Mongoose)
- `coupon = Coupon.objects.filter(code=code).first(); if coupon: apply(coupon)` (Django)
- `if (couponRepo.findByCode(code) != null) apply();` (Java/Spring)
- `if c, _ := db.QueryCoupon(code); c != nil { Apply(c) }` (Go)
- `if ($coupon = Coupon::where('code', $code)->first()) { apply(); }` (Laravel/PHP)
- `Coupon.find_by(code: code) && apply` (Rails/Ruby)

Read-then-write without atomic guard (race window):
- `if (!coupon.used) { coupon.used = true; coupon.save(); }`
- `if (coupon.usedCount < coupon.maxUses) { coupon.usedCount++; repo.save(coupon); }` — TOCTOU
- `existing = db.user_coupons.find(user_id=user); if not existing: ...` then separate insert

Missing expiry / minimum validation:
- no `coupon.valid_until` / `expires_at` comparison
- `if cart.total >= coupon.min_spend` absent; discount applied before cart total computed
- `Coupon.find_by(code: code)` with no `.where('expires_at > ?', Time.now)`

Client-controlled discount magnitude:
- `discount = float(req.body.discount)` / `parseFloat(body.discount)` accepted from request
- `coupon.percent = req.body.percent` mass-assignment (Rails `permit!`, Spring setter binding, Eloquent `fill($req->all())`)

No per-user binding table:
- absence of a `user_coupons` / `coupon_redemptions` table with a unique index on `(user_id, coupon_id)`

## False positives
- A `user_coupons` (or `coupon_redemptions`) table with a unique constraint on `(user_id, coupon_id)` or `(order_id, coupon_id)`, applied inside the same transaction as the order total — this is the correct pattern.
- Global cap enforced via conditional atomic `UPDATE ... SET used = used + 1 WHERE used < max AND ...` with `affected_rows == 1` checked (MySQL `ROW_COUNT()`, Postgres `RETURNING`, Go `RowsAffected`).
- The coupon is intentionally reusable (a public site-wide promo with no per-user limit) and the business accepts unlimited global redemption — confirm with product intent before flagging.
- Audit logging plus alerts on anomalous reuse exist, and the code is single-use by design with DB constraints backing it.

## Attack scenario
1. Attacker creates an account and places an order with a 20% off code `SAVE20` intended for one use per customer.
2. The endpoint checks `Coupon.findOne({code:'SAVE20'})`, applies the discount, and creates the order — but never records that *this user* redeemed it.
3. Attacker immediately cancels the order (refund issued) and the code is not marked consumed, or simply starts a new cart and re-applies `SAVE20`. The check passes again because the code is still globally "valid".
4. To exploit concurrency, the attacker fires 50 parallel requests against a 1000-redemption "first-come" code; the read-then-write path lets far more than 1000 redemptions through before `used` catches up.
5. Attacker also submits `{"code":"SAVE20","discount":1.0}` or applies the coupon to a 1-cent cart, banking a near-100% discount; the server trusts the client-supplied magnitude and skips the minimum-spend check.

## Impact
- **Confidentiality**: low direct impact; indirect leakage of promo strategy / abuse of referral PII.
- **Integrity**: high — fraudulent discounts, revenue loss,referrer-reward inflation, unbounded stacking draining inventory or margin.
- **Availability**: a global-cap race can exhaust promotional inventory, denying legitimate customers the offer; abuse can also overload the apply endpoint.
- Severity scales with discount magnitude, code prevalence (a viral public code is catastrophic), and whether stacking/self-referral are also permitted — a single reusable percentage coupon on a high-value catalog can be a direct-revenue critical finding.

## Remediation
Track redemption atomically in a per-user binding table, inside the order transaction, and validate every constraint server-side:
```ts
// VULNERABLE — validity-only check, reusable, race-prone
const coupon = await Coupon.findOne({ code: req.body.code });
if (coupon) applyDiscount(coupon, cart);            // no user/usage/expiry/min-spend check

// SAFE — atomic conditional redemption with all guards
const redeem = await db.transaction(async (tx) => {
  // atomic decrement of the global counter
  const updated = await tx.coupon
    .where({ code, validUntil: { gt: new Date() } })
    .whereRaw('used < max_uses')
    .update({ used: db.raw('used + 1') });
  if (updated === 0) throw new Error('invalid or exhausted coupon');
  // unique constraint on (user_id, coupon_id) prevents per-user reuse
  await tx.userCoupon.insert({ userId, couponId: coupon.id }).onConflict().throw();
  if (cart.total < coupon.minSpend) throw new Error('below minimum spend');
  return applyDiscount(coupon, cart);   // discount magnitude is server-derived, never client input
});
```
Mirror the same constraints on the refund/cancellation path so a redeemed coupon is *not* handed back unless business rules allow it. Defense-in-depth: rate-limit the apply endpoint and alert on spikes to catch brute-force and burst-race attacks.

## References
- OWASP ASVS V11.x — Business Logic Security
- OWASP WSTG-BUSL-03 (rate limiting / abuse), WSTG-BUSL-04 (business logic data validation)
- OWASP Cheat Sheet: REST Security (transaction / concurrency controls)
