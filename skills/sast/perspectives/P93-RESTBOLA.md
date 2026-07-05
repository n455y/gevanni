---
id: P93
name: RESTBOLA
refs: ASVS V13.x / WSTG-ATHZ-04 / CS: REST Security (OWASP API1:BOLA)
requires: [backend]
---

# P93 — RESTBOLA

## Overview
Broken Object Level Authorization (BOLA, a.k.a. IDOR) is the #1 API security risk in the OWASP API Top 10 (API1:2023). It occurs when a REST endpoint exposes an object by a user-supplied identifier (`/api/orders/{id}`) and trusts that *authentication* (knowing who the caller is) implies *authorization* (the caller may touch *this* object). The endpoint fetches the object directly — `findById(id)` — without scoping the query by owner, tenant, or role, so any authenticated user can read or mutate any other user's record by guessing or enumerating IDs. The root cause is always the same: object retrieval is keyed on the object ID alone, and the resource-owner relationship is never enforced server-side. Predictable identifiers (sequential integers, exposed UUIDs, leaked document hashes) make the flaw trivially exploitable at scale.

## What to check
- For every endpoint that takes an object ID (`/orders/:id`, `/invoices/:id`, `/users/:id`, `/documents/{uuid}`), does the data-access query scope the result by the caller's identity (`userId`, `tenantId`, `organizationId`, role)?
- Is `findById(id)` / `getById(id)` / `.find(pk)` called with **only** the primary key, ignoring the authenticated principal?
- Does the list endpoint (`GET /orders`) return a different (smaller) set than the detail endpoint (`GET /orders/:id`) allows access to? Inconsistent scoping is a strong tell.
- Are write/mutation endpoints (`PUT/PATCH/DELETE /orders/:id`) authorized the same way as reads, or are they more permissive?
- Are IDs predictable (sequential integers)? If so, is there per-object authorization to compensate? GUIDs alone are **not** authorization.
- Does the endpoint accept user-controlled IDs in the request body (`{"orderId": ...}`, `{"user_id": ...}`) or in nested routes, beyond the obvious path parameter?
- Is mass-assignment possible — can a client overwrite `ownerId`/`userId`/`tenantId` by including it in a `PUT`/`PATCH` body?
- Are admin/internal object references exposed via the same endpoints without an elevated-role gate?
- Does the API return 200 with the object on unauthorized access (information disclosure), or correctly 404?

## Static signals
Direct lookup by ID without owner/tenant scoping:
- Node/Express + Mongoose: `Order.findById(req.params.id)` — **no `userId`/`tenantId` filter**.
- Node/Prisma: `prisma.order.findUnique({ where: { id } })` — no `userId` in the `where`.
- Node/Sequelize: `Order.findByPk(id)`.
- Python/Django ORM: `Order.objects.get(id=...)` / `Order.objects.get(pk=...)` — **no `user=` filter**.
- Python/SQLAlchemy: `session.query(Order).filter_by(id=...).first()` / `session.get(Order, id)`.
- Python/FastAPI: `def get_order(order_id: int, db=Depends(...)): return db.query(Order).get(order_id)`.
- Java/Spring Data: `repository.findById(id)` — **no `findByIdAndOwner(id, owner)`**.
- Java/JPA: `em.find(Order.class, id)`.
- Go/GORM: `db.First(&order, id)` / `db.Where("id = ?", id).First(&order)`.
- Ruby/Rails ActiveRecord: `Order.find(id)` / `Order.find_by(id: id)` — **vs. safe** `current_user.orders.find(id)`.
- PHP/Laravel Eloquent: `Order::find($id)` — **vs. safe** `auth()->user()->orders()->findOrFail($id)`.
- C#/EF Core: `context.Orders.Find(id)` / `context.Orders.FirstOrDefault(o => o.Id == id)`.

Mass-assignment / over-postable owner fields:
- Rails: `Order.update(params[:order])` with strong-params missing `permit()` filtering of `user_id`/`tenant_id`.
- Laravel: `$order->update($request->all())` without `$request->only([...])` / `$fillable`.
- Spring: `@ModelAttribute Order order` / `@RequestBody` POJO binding `ownerId` without DTO allow-list.
- Django: `form = OrderForm(request.POST, instance=o)` where `fields = '__all__'`.
- Express/Sequelize: `Order.update(req.body, { where: { id } })` with no allow-list.

Predictable identifiers:
- Auto-increment integer PKs (`id SERIAL`, `BIGINT AUTO_INCREMENT`) exposed directly in URLs.
- UUIDs generated with weak/leaked seeds, or stored in client-visible tokens/JWTs.

## False positives
- The data-access query is consistently scoped: `current_user.orders.find(id)`, `Order.findOne({ _id, userId })`, `repository.findByIdAndOwner(id, owner)`, `.filter(user=request.user)` — confirm the scope is applied on **every** code path (read, update, delete).
- The endpoint enforces a role/policy gate before lookup (CASL, Oso, Spring Security `@PreAuthorize`, AWS IAM, custom ACL) that verifies ownership.
- The object is genuinely public/world-readable by design (published article, public profile) and mutation is disabled — confirm writes are still scoped.
- The ID is a capability token (long random, unguessable, server-bound to the owner) AND the lookup checks it as an opaque handle, not a guessable resource ID. (Random IDs without an authz check are still BOLA — enumeration is just slower.)
- A multi-tenant framework (e.g. Apartment, Citus, row-level security in Postgres, Supabase RLS) transparently injects the tenant filter — verify the policy is actually active for this table/session.

## Attack scenario
1. Attacker authenticates as a normal user and observes their own order at `GET /api/orders/1001`.
2. They decrement the ID: `GET /api/orders/1000` returns **another customer's** order (200 OK) because `findById` ignores the caller.
3. They walk the integer range with a script (`1000..9999`), harvesting every order in the system — names, addresses, totals.
4. For mutation, `PUT /api/orders/1000` with `{"status":"refunded"}` modifies someone else's order; `DELETE /api/orders/1000` removes it.
5. If `ownerId` is mass-assignable, `PATCH /api/orders/1000` with `{"userId": <attacker>}` transfers ownership of the victim's resource to the attacker.

## Impact
- **Confidentiality**: full read of any user's / tenant's data (PII, financial records, medical records) — a single unscoped endpoint leaks the entire dataset.
- **Integrity**: arbitrary modification or deletion of other users' records; privilege escalation if admin objects are reachable.
- **Availability**: bulk deletion or lockout of victim resources.
- Severity is typically **High to Critical**: exploitation requires only a valid account (often a free signup), and integer IDs make the entire object space enumerable in seconds.

## Remediation
Scope every lookup by the authenticated principal; prefer framework relationship traversal over raw `findById`:
```ts
// VULNERABLE — fetch by ID alone, any authenticated user reads any order
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});

// SAFE — object-level authorization: scope the query by owner
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
  if (!order) return res.status(404).end(); // 404, not 403, to avoid enumeration oracle
  res.json(order);
});
```
Prefer unguessable identifiers (UUIDv4) over sequential IDs to slow enumeration — but **never as a replacement** for authorization checks. As defense-in-depth, enable per-tenant row-level security at the database (Postgres RLS), use an explicit allow-list for mass-assignment (`$fillable` / strong params / DTO), and add automated tests asserting cross-user access returns 404.

## References
- OWASP ASVS V13.x — API and Web Service protection (incl. V4.1/V13.1 object-level access control)
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References
- OWASP Cheat Sheet: REST Security, Injection Prevention (mass-assignment)
