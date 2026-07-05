---
id: P81
name: StateTransitionBypass
area: V2 Validation and Business Logic
refs: ASVS V11.x / WSTG-BUSL-02, WSTG-BUSL-05 / CS: REST Security, Transaction Authorization
requires: [backend]
---

# P81 — StateTransitionBypass

## Overview
State-transition (business-logic) bypass occurs when the server allows an object's lifecycle state — order, application, workflow, payment, account — to be driven directly by client-supplied input, or moved along a path that skips required preconditions (e.g. paid → shipped without payment, submitted → approved without review, draft → published without moderation). The server becomes a passive persistence layer instead of an authoritative state machine. Unlike injection, the requests are individually "valid" — the flaw is that a forbidden *sequence* is accepted, which automated scanners and schema validators almost never detect. The root cause is missing server-side transition guards: no allow-list of `(from → to)` edges, no precondition checks, no idempotency/locking on the current state.

## What to check
- Is `status` / `state` / `stage` updated directly from `req.body`, `req.params`, `request.json`, or a form field rather than derived from an explicit action verb (`submit`, `approve`, `cancel`)?
- Is there an explicit allow-list of valid transitions (`draft → submitted`, `submitted → approved`) and does the code reject everything else with a `409 Conflict`?
- Are preconditions enforced *before* the transition — e.g. cannot ship until `payment.status == 'paid'`; cannot approve until all reviews `signed`; cannot close until `balance == 0`?
- Is the current state read with row-level locking (optimistic version / `SELECT ... FOR UPDATE`) so two concurrent transitions cannot both succeed (race / TOCTOU)?
- Does the workflow trust the client to drive ordering ("client controls transitions, server is passive")? Look for SPA apps that send the full object back with a new status.
- Are higher-privilege steps gated by an authorization check tied to the transition itself, not just the endpoint? (A normal user calling `/admin/approve` should fail at the *action*, not only at route authz.)
- Are money/critical transitions idempotent and logged with before/after state for audit?

## Static signals
Direct state assignment from request input:
- Node/Express: `order.update({ status: req.body.status })`, `await Order.save(req.body)`
- Python/Django: `order.status = request.POST['status']`, `OrderForm(request.POST)` with `status` in `fields`, `Order.objects.filter(id=...).update(status=request.data['status'])`
- Python/DRF: a `ModelSerializer` with `fields = '__all__'` covering a `status`/`state` column
- Java/Spring: `order.setStatus(dto.getStatus())`, `@ModelAttribute Order order` binding a setter
- Go: `order.Status = req.Body.Status` then `db.Save(&order)`
- PHP/Laravel: `Order::find($id)->update($request->all())`, `$order->fill($request->validated())` with `status` mass-assignable
- Ruby/Rails: `order.update!(order_params)` where `order_params` permits `:status`

Missing transition guard / preconditions:
- No `canTransition(from, to)` / `assert_state` / state-machine helper anywhere near the mutation
- No check on related entities (`payment`, `review`, `invoice`) before advancing
- ORM mass-assignment without `$guarded`/`$fillable`/`@JsonIgnore`/`read_only` on the state field
- Patch/PUT endpoints accepting arbitrary field sets including `status`

Frameworks to confirm are *enforcing*:
- Django FSM / Rails AASM / XState / Spring Statemachine / Laravel workflows — the safe variant; verify the transition is invoked through the library's `.transition()`/`.fire()` API, not bypassed by a raw update.

## False positives
- A server-side state machine (Django-FSM, AASM, Spring Statemachine) guards transitions and rejects invalid edges with an exception; the persistence layer never writes arbitrary `status`.
- Precondition assertions exist and are tested (e.g. `if order.paid_at is None: raise InvalidTransition`), and the state field is excluded from mass-assignment / serializer writable fields.
- The endpoint accepts only an *action* enum (`POST /orders/:id/ship`) resolved server-side, never a raw `status` value.
- The field is purely cosmetic/display state with no authorization, billing, or workflow consequence (still worth flagging, but low severity).

## Attack scenario
1. Attacker, a normal customer, places an order. The normal flow is `created → paid → shipped → delivered`.
2. Attacker inspects the update request (`PATCH /orders/123`) and notices the body `{"status": "shipped"}` is accepted verbatim.
3. Attacker sends `PATCH /orders/123` with `{"status": "shipped"}` **without ever paying**. The server sets `order.status = 'shipped'`.
4. The fulfillment pipeline reads `status == 'shipped'` and dispatches the goods, or a downstream system issues a license/invoice. The attacker receives the product for free.
5. Variant: in an approval workflow, attacker posts `{"status": "approved"}` to skip manager review, or `{"status": "closed"}` to lock a dispute in their favor.

## Impact
- **Integrity**: fraudulent orders, skipped payments/pay-outs, bypassed approval/moderation/KYC, double-spending of coupons or credits — the most common real-world outcome.
- **Confidentiality**: access to states the user should not reach (e.g. jumping to `completed` reveals internal review notes, signed contracts, or PII attached to that state).
- **Availability**: corrupting state (e.g. setting an account to `closed`/`suspended`) can lock users out or wedge background workers.
- Severity scales with the value of the asset behind the state: billing/shipping/approval transitions are typically High/Critical; cosmetic display state is Low.

## Remediation
Drive state from explicit actions through a guarded state machine; never bind `status` from request data:
```ts
// VULNERABLE — client dictates the state directly
app.patch('/orders/:id', async (req, res) => {
  const order = await Order.find(req.params.id);
  order.status = req.body.status;          // attacker: "shipped" with no payment
  await order.save();
  res.json(order);
});

// SAFE — allow-listed edges, precondition check, row lock
const ALLOWED = {
  created: ['paid'],
  paid:    ['shipped'],
  shipped: ['delivered'],
};
app.post('/orders/:id/ship', async (req, res) => {
  const order = await Order.find(req.params.id, { lock: true });
  if (!ALLOWED[order.status]?.includes('shipped')) return res.status(409).end();
  if (order.payment.status !== 'paid')           return res.status(409).end();
  await order.transition('shipped');             // logged: before -> after
  res.json(order);
});
```
Exclude the state column from mass-assignment (`fillable`/`fields = (...)`/`read_only=['status']`), and emit an append-only audit log of every transition with actor, timestamp, and before/after values. Add optimistic locking (`version`/`etag`) so concurrent transition requests cannot both succeed.

## References
- OWASP ASVS V11.x — Business Logic Security / race conditions
- OWASP WSTG-BUSL-02 — Testing for Business Logic / Workflow Bypass; WSTG-BUSL-05 — Testing for Process Timing
- OWASP Cheat Sheets: REST Security, Transaction Authorization
