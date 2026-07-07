---
id: P80
name: PriceQuantityTrust
refs: ASVS V11.x / WSTG-BUSL-01, WSTG-BUSL-04 / CS: REST Security, Transaction Authorization
---

# P80 — PriceQuantityTrust

## Preconditions

The code handles values supplied by the client that affect transactions.


## Overview
Price/quantity/discount/currency trust occurs when a server treats order-critical monetary fields received from the client — price, unit cost, quantity, tax, discount, shipping fee, total, or currency code — as authoritative instead of recomputing them server-side from a trusted product/pricing master. The root cause is conflating *user input* (what the client chooses: product ID, quantity) with *server-controlled truth* (what each item costs, how tax is applied). Because the client fully controls these values (DevTools, proxy, replay), trusting them lets an attacker buy goods for 0.01, inflate quantity without cost, apply a discount twice, or switch currency to devalue a charge. This is a business-logic flaw, not an injection bug — encoding and validation lists alone do not fix it; the price must be re-derived from a server-owned source on every request.

## What to check
- Does any checkout/payment/order endpoint read `price`, `amount`, `total`, `tax`, `discount`, `shipping`, or `currency` directly from the request body / query / cookie / hidden form field and pass it to the charge or persistence layer?
- Is the unit price re-fetched from a server-side product/pricing master keyed only by `productId` (and optionally tier/region), with the client-supplied price ignored entirely?
- Is `quantity` validated as a positive integer (or allowed fraction) within sane bounds, and is the total computed server-side as `unit_price * quantity`?
- Are discounts/coupons validated server-side — existence, expiry, single-use, per-user limits, currency match, and stacking rules — rather than trusting a client-supplied `discount` or `discountPercent`?
- Are tax, fees, and totals recomputed server-side (never read from the client), and is the final charged amount derived from server state, not echoed from the request?
- Is the currency validated against an allow-list, and does the server enforce that the charged currency matches the product/region currency (no FX manipulation)?
- Are negative quantities/amounts rejected? Is zero-price (free) ordering an intentional, allow-listed path or an unintended gap?
- For refunds/partial-cancellations, is the refund amount bounded by the original server-recorded charge, not the client's claimed amount?
- Is there a server-side idempotency/order record so the same cart cannot be replayed with tampered totals?
- For auction/offer/quote flows, is the accepted price anchored to a server-signed quote with expiry rather than a raw client value?

## Static signals
Direct use of client monetary fields in charge/persist calls:
- Node/Express: `charge(user, req.body.amount)`, `stripe.charges.create({ amount: req.body.total })`,
  `Order.create({ total: req.body.total, price: req.body.price })`,
  `parseInt(req.body.qty)` with no bound check.
- Python/Django/Flask: `charge(user, request.POST['amount'])`,
  `Order.objects.create(total=request.data['total'])`,
  `f"{request.json['price']}"` written to invoice.
- Java/Spring: `charge(user, request.getBody().getAmount())`,
  `new Order(req.getParameter("total"))`, `BigDecimal total = dto.getTotal();` where `dto` is a `@RequestBody` bound from client.
- Go: `amount := req.FormValue("amount")` passed straight to `Charge(amount)`.
- PHP/Laravel: `Charge::create(['amount' => $request->input('total')])`, `Order::create($request->all())` (mass-assignment of `total`/`price`).
- Ruby/Rails: `Order.create!(amount: params[:amount])`, `charge(user, params[:total])`.

Quantity/total read without re-derivation:
- `total = req.body.price * req.body.quantity` (both operands client-supplied — price must come from master).
- `qty = int(req.POST['qty'])` with no `qty > 0` / `qty <= max` guard.
- Negative-value acceptance: `if qty < 0:` missing; `abs()` absent before multiplying.

Discount/coupon trust:
- `discount = req.body.discount`, `applyCoupon(req.body.code, req.body.discountValue)`,
  `total -= request.json['discount']` without server lookup of the coupon record.
- Reuse: no check that the coupon belongs to the user or has not already been redeemed.

Currency trust:
- `currency = req.body.currency`, `Charge(amount, req.body.currency)` with no allow-list / no product-currency match.
- FX tricks: client sets `currency=JPY` with `amount` in cents/units mismatched to the gateway.

Mass-assignment / over-trusting DTOs:
- `Order.create(req.body)` / `Order::create($request->all())` / `$model->fill($input)` letting `price`/`total`/`paid` be overwritten.
- JPA entity exposing a settable `price`/`total` column populated directly from a request DTO.

## False positives
- The server re-fetches the product by `productId` from a trusted master, recomputes `total = product.price * qty`, recomputes tax/discount server-side, and uses *that* value to charge — the client `price`/`total` fields are ignored or only echoed for display.
- Quantity is validated as a positive integer within `[1, stock_or_max]` and bounded; negative/zero are rejected.
- Coupons are looked up server-side with expiry, single-use, per-user, currency, and stacking rules enforced; the client only sends the coupon code.
- Donation / "pay-what-you-want" flows where the user legitimately sets the amount — confirm a non-trivial lower/upper bound and that the amount is signed/canonicalized before reaching the gateway.
- Refund amount is taken from the original server-recorded charge record (not the client) and bounded by remaining balance.
- The accepted price comes from a server-signed quote/offer with expiry (e.g., signed JWT/signed URL) whose integrity is verified before charging.

## Attack scenario
1. Attacker opens the store, adds a normal item, and intercepts the `POST /api/checkout` with a proxy (Burp) or edits the request in DevTools.
2. The original body is `{"productId":"P123","qty":1}` and the client also sends `{"price":0.01,"total":0.01}`. The attacker sets `"price":1, "qty":1, "total":1` for a $500 item — or `"qty":-5"` to issue credit.
3. The server, lacking re-derivation, charges the tampered `total` (1 unit) instead of the product's real price.
4. Alternatively the attacker submits a `discountPercent: 100` or a coupon `code` paired with a client-set `discountValue`, yielding a zero charge, or flips `currency` from USD to a devalued unit while keeping the amount.
5. The order is fulfilled as paid; the attacker receives the goods for a fraction (or for free). Replayed at scale, this is direct revenue loss and inventory drain.

## Impact
- **Confidentiality**: low direct impact, but order/price master leakage may follow if endpoints leak pricing logic.
- **Integrity**: fraudulent orders at attacker-chosen prices; corrupted financial/inventory records; chargeback and refund abuse.
- **Availability**: inventory exhaustion via free/near-free bulk orders; refund storms; gateway or fulfillment overload.
- Severity scales with what can be purchased and the volume: a single underpayment is low; a scriptable bulk exploit against high-value or digital goods (gift cards, subscriptions, withdrawals) is critical and directly monetizable.

## Remediation
Never trust client-supplied monetary fields; re-derive everything server-side from a trusted master:
```ts
// VULNERABLE — client controls the charge amount
app.post('/checkout', async (req, res) => {
  await charge(user, req.body.total);          // total/price/qty all from client
});

// SAFE — price from master, qty validated, totals recomputed server-side
app.post('/checkout', async (req, res) => {
  const qty = Number(req.body.qty);
  if (!Number.isInteger(qty) || qty < 1 || qty > MAX_QTY) return res.status(400).end();

  const product = await Product.findById(req.body.productId); // trusted master
  if (!product || !product.active) return res.status(404).end();

  const coupon = req.body.couponCode
    ? await Coupon.findValid(req.body.couponCode, user.id, product.currency) // server rules
    : null;

  const total = computeTotal({ unitPrice: product.price, qty, coupon, currency: product.currency });
  await charge(user, { amount: total, currency: product.currency }); // server-derived
});
```
Defense-in-depth: enforce an idempotency key + server-side order record for every checkout, reject negative/zero quantities and amounts globally, allow-list currency codes, and reconcile the charged amount against an immutable server order before fulfillment. Apply the same controls to refunds, partial cancellations, and subscription upgrades.

## References
- OWASP ASVS V11.x — Business logic and transaction authorization
- OWASP WSTG-BUSL-01 — Testing for Business Logic / Data Validation
- OWASP WSTG-BUSL-04 — Testing for Process Timing / Price/Quantity Manipulation
- OWASP Cheat Sheets: REST Security, Transaction Authorization
