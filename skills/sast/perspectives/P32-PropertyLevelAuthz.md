---
id: P32
name: PropertyLevelAuthz
area: V8 Authorization
refs: ASVS V4.1.x, V4.3.x / WSTG-ATHZ-03, WSTG-ATHZ-04 / CS: Authorization, Mass Assignment, Insecure Direct Object Reference Prevention
requires: [backend]
---

# P32 — PropertyLevelAuthz

## Overview
Property-level authorization (also called field-level or attribute-level access control) is the discipline of deciding, **per individual field**, whether the current subject may read or write it. Most applications enforce coarse object-level checks ("can this user view/own this record?") but then blindly serialize the entire entity — leaking `passwordHash`, `role`, `isAdmin`, `tenantId`, `mfaSecret`, internal flags, or another tenant's data. The write side is equally dangerous: binding request input directly onto a model (`Object.assign`, mass updaters) lets a low-privilege user flip `role`, `ownerId`, or `balance`. Root causes are (1) returning raw ORM entities instead of projection DTOs, (2) lack of field allow-lists on input binding, and (3) no per-field authz at the serializer/GraphQL-resolver layer. This is distinct from IDOR (object-level) — here the user is *allowed* to see the object, just not every field on it.

## What to check
- Does any handler return a raw ORM/database entity directly (`res.json(user)`, `return repo.find(...)`) without projecting through a serializer or DTO that selects only permitted fields?
- Are sensitive fields ever present in the serialized output: `passwordHash`, `password`, `mfaSecret`/`totpSecret`, `role`, `isAdmin`, `isSuperuser`, `tenantId`, `organizationId`, `emailVerified`, `balance`, `apiKey`, `stripeCustomerId`, audit/internal columns?
- On the write side, is request input bound onto the model wholesale — `Object.assign(user, req.body)`, `user.set(req.body)`, `model.update(request.all())`, `**request.data`, `@ModelAttribute`, `req.body` spread into a builder — without an explicit allow-list of mutable properties?
- Are bulk-update endpoints (`PATCH /users/:id` with arbitrary JSON) restricted to fields the caller's role may change (e.g., a user can edit `name` but not `role`)?
- For GraphQL/API-Platform, is there per-field authz (`@authorized`, field-level directives, custom property access voters) or does any authenticated client resolve every field?
- Are different response shapes served per role (admin vs. self vs. public), or is one DTO reused for all audiences?
- Does the entity carry embedded sub-objects (relations, value objects, other users' references) that get serialized transitively?

## Static signals
Returning raw entities / whole-object serialization:
- Node/Express: `res.json(user)`, `res.send(user)`, `return user` from a controller returning the ORM object
- Sequelize/Mongoose: `User.findByPk(id)` returned without `.toJSON()` projection / `.select('-passwordHash')`
- Python/Django: `return JsonResponse(user.__dict__)`, `User.objects.get(...)` serialized via `model_to_dict(user)` (includes every field), `serializers.serialize('json', [user])`
- DRF: `class UserSerializer(serializers.ModelSerializer` with `fields = '__all__'`
- Java/Jackson: `@JsonIgnore` absent on `passwordHash`/`role`; class annotated `@JsonIgnoreProperties(ignoreUnknown = true)` with no per-field ignore; Spring returning the JPA entity from `@RestController`
- Go: `json.NewEncoder(w).Encode(user)` over a struct whose sensitive fields lack `json:"-"` tags
- Ruby/Rails: `render json: @user` over a model with no per-field filtering; `@user.attributes`
- PHP/Symfony: returning the Doctrine entity from the controller with `Serializer` and no exclusion groups

Unrestricted input binding (mass assignment):
- Node: `Object.assign(user, req.body)`, `user.set(req.body)` (Bookshelf/Objection), `await User.query().patchAndFetchById(id, req.body)`
- Mongoose: `User.findByIdAndUpdate(id, req.body)` with no `select`/schema-guarded paths (`select: false`, `immutable: true`)
- Python: `user = User(**request.json)`, `for k,v in request.json.items(): setattr(user, k, v)`, SQLAlchemy `User(**data)`
- Django ORM: `User.objects.filter(...).update(**request.data)` without a cleaned form
- Java: `@PostMapping public void update(@ModelAttribute User user, ...)`; `BeanUtils.copyProperties(dto, entity)` over all fields
- Spring Data REST: a `@RepositoryRestResource` exposing a full POST/PATCH with no `@JsonIgnore` / `@Setter(AccessLevel.PROTECTED)`
- Ruby/Rails: `User.update(params[:user])` from `params.require(:user).permit!` (or no strong-params filter)
- Go: `json.NewDecoder(r.Body).Decode(&user)` straight onto the model struct, including `Role`, `ID`, `OwnerID`
- PHP/Laravel: `$user->update($request->all())` instead of `$request->only(['name','email'])` (fillable vs. guarded misuse)
- C#/.NET EF: `[Bind]` absent on the action; `TryUpdateModelAsync(user)` updating every public property

## False positives
- A DTO/serializer with an explicit field allow-list (e.g., DRF `fields = ['id','name','email']`, Java record projection, Mongoose `.select('id name email')`) is used — non-listed fields never serialize.
- Mass-assignment is prevented by framework defaults: Laravel `$fillable`/`$guarded`, Rails strong params `.permit(:name, :email)`, Mongoose `select: false`/`immutable`, EF `[NeverSerialize]`/`[BindNever]`, Spring `@JsonIgnore` on setters.
- GraphQL field-level authz is enforced (`@auth`, `@canAccess`, Shield rules) and resolvers short-circuit forbidden fields before serialization.
- The endpoint genuinely serves an admin-only audience behind an object+role check, and exposing `role`/`tenantId` is intended.
- The model has no sensitive fields at all (a pure public-content entity like `Article`).

## Attack scenario
1. A normal authenticated user requests their own profile: `GET /api/users/123`.
2. The handler returns the raw ORM entity: `res.json(user)`. The response includes `role:"user"`, `tenantId`, `emailVerified`, and `mfaSecret`.
3. The user sends `PATCH /api/users/123` with body `{"role":"admin","tenantId":999,"balance":1000000}`.
4. The handler does `Object.assign(user, req.body); await user.save()` (no field allow-list).
5. `role` flips to `admin`; the user now passes every `requireRole('admin')` gate — full privilege escalation and cross-tenant access.

## Impact
- **Confidentiality**: leakage of credentials/secrets (`passwordHash`, `mfaSecret`, `apiKey`), internal identifiers, and other tenants' or users' embedded data.
- **Integrity**: privilege escalation (`role`/`isAdmin`), account takeover (`password`/`email` write), cross-tenant data moves (`tenantId`/`ownerId`), balance/quota tampering.
- **Availability**: quota/billing corruption, resource exhaustion via arbitrary flags.
- Severity ranges from informational (cosmetic field leak) to **critical** (mass-assignment privilege escalation to admin). The read path is usually medium-to-high; the write path is frequently critical.

## Remediation
Never return raw entities; always project through a serializer with an explicit allow-list. Never bind input onto the model wholesale.
```ts
// VULNERABLE — whole entity returned + mass assignment
app.get('/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  res.json(user);                 // leaks passwordHash, role, tenantId, ...
});
app.patch('/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  Object.assign(user, req.body);  // caller can set role, balance, ...
  await user.save();
  res.json(user);
});

// SAFE — projection DTO + field allow-list on write
const PUBLIC_FIELDS = ['id', 'name', 'email'] as const;
app.get('/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  res.json(pick(user, PUBLIC_FIELDS));
});
app.patch('/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  Object.assign(user, pick(req.body, ['name', 'email'])); // role never mutable here
  await user.save();
  res.json(pick(user, PUBLIC_FIELDS));
});
```
Apply defense-in-depth at the model layer too: mark secrets with `@JsonIgnore`/`select: false`/`json:"-"`/`#[SensitiveParameter]`, and make `role`/`ownerId` non-settable from generic update paths (immutable, separate privileged endpoint, separate DTO per role). For GraphQL, enforce field-level authz so resolvers reject forbidden fields before serialization.

## References
- OWASP ASVS V4.1.x (general access control), V4.3.x (access control per operation/field) — verify field-level and attribute-level authorization
- OWASP WSTG-ATHZ-03 (Bypassing Authorization Schema), WSTG-ATHZ-04 (Insecure Direct Object References) — covers over-exposure and mass-assignment vectors
- OWASP Cheat Sheets: Authorization, Mass Assignment, Insecure Direct Object Reference Prevention
