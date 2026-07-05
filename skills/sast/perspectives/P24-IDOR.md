---
id: P24
name: IDOR
refs: ASVS V4.1.x, V4.2.x, V4.3.x / WSTG-ATHZ-01, WSTG-ATHZ-04 / CS: Insecure Direct Object Reference Prevention
requires: [backend]
---

# P24 — IDOR

## Overview
Insecure Direct Object Reference (IDOR) occurs when an application exposes a reference to an internal object — a database primary key, file name, UUID, or sequential identifier — in a client-controllable input (path, query, body, or header) and then uses that reference to fetch or mutate a resource **without verifying that the requesting user is authorized to act on it**. The root cause is a missing or insufficient server-side authorization check: the application conflates "the object exists" with "the user may access it." Because object IDs are often enumerable (incrementing integers, leaked UUIDs, predictable GUIDs), an authenticated attacker can walk the keyspace to read, modify, or delete other users' data. IDOR is the most common manifestation of Broken Access Control, consistently the #1 risk in the OWASP Top 10, and a server-side flaw that cannot be fixed by encryption, encoding, or obfuscation alone.

## What to check
- For every handler that takes an object identifier (`req.params.id`, `req.body.orderId`, query `?invoice=`, header `X-Account-Id`), does the code enforce an **ownership or role check** server-side before returning or mutating the record?
- Is the authorization bound to the *authenticated principal* (e.g. `req.user.id`) rather than to a field the client can supply (e.g. a body `userId` or a JWT claim the client could tamper with)?
- Are all CRUD verbs covered? A common bug is checking `GET` but leaving `PUT`/`PATCH`/`DELETE` unprotected (or vice-versa).
- For list/index endpoints, is the result set filtered by the caller's tenant/account (`WHERE owner_id = ?`), or does it return all rows regardless of requester?
- Does the query include an ownership predicate (`AND user_id = :current`) **in the same statement** that loads the object, rather than loading then checking in a separate step that can short-circuit or be skipped?
- Are non-DB resources also protected — file downloads keyed by path (`/files/<id>.pdf`), signed-but-unscoped URLs, cloud object-storage keys, internal API references?
- Do indirect references, GUIDs, or encrypted tokens actually enforce authorization, or do they only *obfuscate*? Security through obscurity is not a control.
- Is there a horizontal-escalation path (peer user → peer user) and a vertical-escalation path (regular user → admin object)? Check both.
- Are bulk/batch endpoints (`POST /api/orders/batch` with an array of IDs) authorized per-element, not just at the collection level?
- Could a user pass *someone else's* identifier in a body field to reassign ownership (mass-assignment / `ownerId` tampering) — see also P-passing-untrusted-data-to-constructors?

## Static signals
Loading by client-supplied ID with **no ownership predicate**:
- Node/Mongoose: `Model.findById(req.params.id)`, `Model.findOne({ _id: req.params.id })`
- Node/Prisma/Sequelize: `prisma.post.findUnique({ where: { id: req.params.id } })`, `Post.findByPk(req.params.id)`
- Python/Django: `Model.objects.get(id=request.GET['id'])`, `get_object_or_404(Model, pk=kwargs['pk'])` without a `user=` / `owner=` filter
- Python/SQLAlchemy: `session.query(Model).filter(Model.id == req_id).first()`
- Java/Spring Data: `repository.findById(id)`, `repo.findOne(id)` — no `findByOwner_IdAndId(...)`
- Go: `db.First(&model, id)`, `db.Where("id = ?", id).First(&model)`
- Ruby/Rails: `Model.find(params[:id])`, `Model.find_by(id: params[:id])`
- PHP/Laravel: `Model::find($id)`, `Model::where('id', $id)->first()`
- C#/EF: `_context.Users.Find(id)`, `_context.Orders.FirstOrDefault(o => o.Id == id)` without a user clause

SQL with client value in `WHERE` but **no `owner_id`/`user_id` clause**:
- `WHERE id = ?` (single-key load, no ownership)
- `SELECT * FROM invoices WHERE invoice_id = :id` — missing `AND user_id = :uid`
- Raw string concatenation: `f"SELECT ... WHERE id = {request.GET['id']}"` (also SQL injection — see P-sql-injection)

Body/claim used as the *identity* source instead of the authenticated session:
- `const userId = req.body.userId;` then load by it
- `SELECT ... WHERE user_id = ?` where `?` comes from `request.json['user_id']` or a query param, not `req.user.id`
- JWT claim used as the ownership key but not re-validated server-side (`const ownerId = jwtDecode(req.headers.authorization).uid`)

Missing-verb coverage — guard present on `show` but not `update`/`destroy`:
- `@app.route('/orders/<int:id>', methods=['PUT'])` with no decorator/guard
- Spring `@PutMapping("/{id}")` calling `repo.save(...)` with no `@PreAuthorize` or ownership check

Mass-assignment enabling ownership rewrite:
- `Model.objects.filter(id=...).update(**request.POST)` / `Model.update(...req.body)` where `req.body` may contain `ownerId`/`user_id`

## False positives
- A real, centralized authorization layer is invoked for every path: Spring Security `@PreAuthorize("@orderRepo.isOwner(authentication, #id)")`, Rails `current_user.orders.find(...)`, Django `get_object_or_404(Model, pk=pk, owner=request.user)`, Laravel `User::find($id)->posts()->findOrFail($postId)`, or a policy/guard (Pundit, Cancancan, Casbin, OPA) enforced at the framework boundary.
- The load query scopes by the authenticated user in the *same statement* — `findOne({ _id, owner: req.user.id })`, `WHERE id = ? AND user_id = ?` — so a non-owner ID simply returns 404.
- The endpoint is intentionally public/admin and gated by a separate, verified role check (e.g. `if (req.user.role !== 'admin') return 403` before the load). Confirm the admin guard actually fires on this route and that role comes from the server, not a client claim.
- The object reference is a capability token — long, random, server-scoped-to-this-user, and revocable (e.g. a signed download URL tied to the user). Bare incrementing IDs and exposed UUIDs are NOT capability tokens.
- The resource is genuinely global/shared (a public profile, a master config table) and there is no per-user data to protect.

## Attack scenario
1. Attacker authenticates as their own account (`attacker@example.com`, user id 1002) and notes that viewing an invoice uses `GET /api/invoices/5512`.
2. The handler does `Invoice.findById(req.params.id)` and returns the row — no `WHERE user_id = ?`.
3. Attacker decrements/increments the path: `/api/invoices/5511`, `5510`, ... each returns another user's invoice (amounts, billing address, PII).
4. Attacker finds the matching `PUT /api/invoices/5511` and `DELETE /api/invoices/5511` are equally unguarded, enabling modification/cancellation of victims' invoices (horizontal escalation).
5. By enumerating toward low IDs (1, 2, 3) the attacker may hit admin or system records (vertical escalation), pivoting to full account compromise or fraud.

## Impact
- **Confidentiality**: bulk extraction of other users' PII, financial records, medical data, private messages, API keys stored per-user. IDs are enumerable, so leakage is often the entire table.
- **Integrity**: modification or deletion of others' records — fraudulent edits, account-data tampering, destruction of evidence, privilege changes via mass-assignment.
- **Availability**: destructive mass-delete of victims' resources; denial of service on shared objects.
- Severity scales with data sensitivity and reachability: a single unprotected admin-object endpoint can become full compromise; unscoped list endpoints expose the whole tenant dataset at once. Often rated High/Critical.

## Remediation
Enforce authorization in the same query/statement that loads the object; prefer framework-scoped relations or a dedicated policy layer:
```ts
// VULNERABLE — loads by ID alone, no ownership check
app.get('/invoices/:id', async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);   // any user, any invoice
  res.json(invoice);
});

// SAFE — ownership predicate bound to the authenticated principal in the same query
app.get('/invoices/:id', async (req, res) => {
  const invoice = await Invoice.findOne({
    _id: req.params.id,
    ownerId: req.user.id,                                  // scoped to the caller
  });
  if (!invoice) return res.sendStatus(404);                // hide existence from non-owners
  res.json(invoice);
});
```
Apply the same pattern across all verbs (`PUT`/`PATCH`/`DELETE`), use a central authorization layer (Spring Security, Pundit/Cancancan, OPA, Casbin) rather than ad-hoc checks, and prefer opaque unscoped capability tokens over enumerable IDs for sensitive resources — but always keep the server-side ownership check as the primary control; obfuscation alone is not security.

## References
- OWASP ASVS V4.1.x (general access control), V4.2.x (operation-level), V4.3.x (field/object-level authorization)
- OWASP WSTG-ATHZ-01 (directory traversal/file inclusion boundary), WSTG-ATHZ-04 (testing for bypassing authorization schema / IDOR)
- OWASP Cheat Sheet: Insecure Direct Object Reference Prevention
