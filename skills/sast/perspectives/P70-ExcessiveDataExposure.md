---
id: P70
name: ExcessiveDataExposure
area: V14 Data Protection
refs: ASVS V8.3.x, V4.3.x / WSTG-ATHZ-03, WSTG-INFO-02 / CS: REST Security, REST Assessment
requires: [backend]
---

# P70 — ExcessiveDataExposure

## Overview
Excessive Data Exposure (an API-focused weakness, OWASP API1:2023 Broken Object Level Authorization's sibling) happens when an API endpoint returns **more data than the caller is authorized to see** — internal fields, other users' records, audit/metadata, or deeply populated related objects. The root cause is rarely a missing access check on the request; it is the serializer. The handler correctly authorizes "may user X fetch order 123?" and then blindly serializes the entire ORM entity, leaking fields (password hash, internal notes, `createdAt`/`tenantId`, PII of nested objects) the client UI never displays. Unlike injection, there is no crafted payload — the attacker simply reads the JSON. BOLA exploits broken authorization to reach an object; excessive data exposure leaks fields of an object the user was legitimately allowed to fetch.

## What to check
- Does any handler return an ORM entity / domain model directly (e.g. `res.json(user)`) instead of a DTO/view-model that whitelists fields?
- Are all fields of the serialized object meant for the requesting role? Check for `password`, `passwordHash`, `salt`, `secret`/`apiKey`, `mfaSecret`, `token`, `ssn`, `taxId`, internal notes, `isStaff`/`isAdmin`, `tenantId`, soft-delete flags.
- Does a list endpoint paginate, filter, and field-select, or does it return every row with every column?
- Are related objects auto-populated/joined (Mongoose `.populate`, Sequelize `.include`, Prisma `include`/`select`, Django `.select_related`/`.prefetch_related`, JPA `FetchType.EAGER`, Rails `includes`/`as_json`) such that a parent response embeds sensitive children?
- Do admin and ordinary-user clients share the same serializer (admin-only fields leak to regular users)?
- Is sensitive data returned in error/exception bodies, stack traces, or debug envelopes?
- Does the API honor client-controlled field selection (`?fields=password,email` / GraphQL query depth/fields) without server-side authorization on each requested field?
- Are audit/log/health/debug endpoints (`/actuator`, `/admin`, `/_debug`) exposing internals without authentication?

## Static signals
Whole-entity serialization (no field whitelisting):
- Node/Express: `res.json(user)`, `res.json(await User.find())`, `res.send(user.toJSON())`
- Python/Django: `return JsonResponse(model_to_dict(obj))`, `Serializer(user).data`, `Model.objects.all()` returned in a list view without `fields = (...)`
- Python/FastAPI/Pydantic: a response model with `model_config = ConfigDict(from_attributes=True)` (`orm_mode`) returning the ORM object directly — leaks every ORM column unless `response_model`/`fields` are restricted.
- Java/JPA: `return ResponseEntity.ok(entity)` / Jackson serializing an `@Entity`; `@JsonIgnore` missing on `passwordHash`.
- Go: `json.NewEncoder(w).Encode(user)` with the struct having JSON-exported sensitive fields (no `json:"-"` tag).
- Ruby/Rails: `render json: @user` or `render json: @user.as_json` (the default `as_json` exposes all columns).
- PHP/Laravel: `return response()->json($user)` / `UserResource` without a `only(...)`/`transform` allow-list; `return $model` from a controller.

Deep population leaking nested sensitive data:
- Mongoose `User.find().populate('organization')` / `.populate({ path: 'orders', populate: ... })`
- Prisma `prisma.user.findUnique({ include: { accounts: true, sessions: true } })`
- Sequelize `User.findAll({ include: [{ model: Order, include: [Payment] }] })`
- Django `User.objects.prefetch_related('orders__payments')`
- Rails `render json: @user, include: { orders: { include: :payments } }`

Client-controlled field selection without per-field authorization:
- `req.query.fields.split(',').forEach(f => payload[f] = user[f])` — mass-assign from query string into the response.
- GraphQL without field-level authorization directives (`@auth`/`@authorized`/`@authz`) or depth/complexity limits — clients can request `user { passwordHash }` directly.
- Spreads: `res.json({ ...user._doc })`, `return { **user.__dict__ }`, `return { ...entity }` — copies every attribute including secrets.

## False positives
- A DTO/serializer explicitly whitelists fields per role (`UserPublicDTO`, `select: { password: false }`, `@JsonIgnore` on secrets, Rails `as_json(only: [:id, :name])`, Go `json:"-"` tags) and that allow-list is the only path to the response.
- The field is genuinely public (display name, avatar URL) and a threat model confirms non-sensitivity.
- GraphQL has field-level authorization (`@authorized` / `@authz` directives, graphql-shield rules) AND query complexity/depth limits AND introspection disabled in production — then deep queries are bounded.
- The endpoint is an internal/admin surface behind its own strict authz and returns the full entity intentionally, with logging.
- Pagination + server-side `select` + max page size are all enforced, so a list endpoint cannot dump the whole table.

## Attack scenario
1. Attacker authenticates as a normal user and calls `GET /api/users/me`.
2. The handler does `const user = await User.findById(req.user.id); res.json(user);` — the serializer emits every column.
3. The response JSON contains `passwordHash`, `mfaSecret`, `backupCodes`, `apiKey`, and an embedded `organization.stripeSecretKey` from a stray `.populate`.
4. Attacker cracks the password hash offline (or reuses the leaked `apiKey`) to pivot to other accounts / billing.
5. Attacker also enumerates via `GET /api/users?fields=passwordHash` (server honors `fields=` without authorization) and harvests hashes for the entire user table.

## Impact
- **Confidentiality**: direct, high-severity leakage of credentials, PII, financial data, secrets, and other tenants' data. Often the single most damaging API finding.
- **Integrity**: leaked `apiKey`/`admin`/`mfaSecret` enable account takeover, privilege escalation, fraudulent actions as the victim.
- **Availability**: limited direct impact, but leaked operational secrets (DB creds, cloud keys) can lead to full environment compromise and service destruction.
- Severity scales with the leaked fields: a display-name leak is informational; a password-hash or cloud-key leak is Critical and cascades into BOLA/ATO of every user.

## Remediation
Never serialize ORM entities directly; project to an allow-listed DTO per role:
```ts
// VULNERABLE — whole entity + deep population, leaks passwordHash etc.
app.get('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id).populate('organization');
  res.json(user);
});

// SAFE — role-aware DTO, explicit field selection, sensitive fields excluded
const PUBLIC_FIELDS = ['id', 'name', 'avatarUrl'] as const;
const ADMIN_FIELDS  = [...PUBLIC_FIELDS, 'email', 'role', 'createdAt'] as const;

app.get('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id).select('-passwordHash -mfaSecret');
  if (!user) return res.status(404).end();
  const fields = req.user.role === 'admin' ? ADMIN_FIELDS : PUBLIC_FIELDS;
  res.json(pick(user.toObject(), fields)); // pick() = strict allow-list projection
});
```
Layered controls: define one serializer per role; disable client-controlled `fields=` (or authorize each requested field server-side); apply GraphQL field-level authz plus depth/complexity limits; strip secrets and stack traces from error envelopes; audit log/health/debug endpoints separately. Defense-in-depth: redact secrets at the ORM level (`@JsonIgnore` / `select: false` / `json: "-"`) so a forgotten serializer cannot resurrect them.

## References
- ASVS V8.3.x, V4.3.x
- WSTG-ATHZ-03, WSTG-INFO-02
- CS: REST Security, REST Assessment
