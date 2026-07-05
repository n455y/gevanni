---
id: P50
name: MassAssignment
refs: ASVS V5.3.x / WSTG-INPV-12 / CS: Mass Assignment, REST Security
requires: [backend]
---

# P50 — Mass Assignment

## Overview
Mass assignment occurs when a framework auto-binds an entire client-supplied payload (`req.body`, form fields, JSON) onto a domain object — directly or via the ORM — **without an explicit allow-list of the fields the caller is permitted to set**. Because object-relational mappers and "serialize-into-model" helpers copy every key they receive, any attribute that exists on the model becomes writable by the client, including privileged fields the developer never intended to expose: `role`, `isAdmin`, `password`, `balance`, `tenantId`, `verifiedAt`, `price`, `paymentStatus`. The root cause is not a missing check on one field — it is trusting the *shape* of the request. The fix is always input shaping: pick exactly the keys the action is allowed to mutate, and reject or ignore everything else. A related failure is prototype pollution (`__proto__`, `constructor`, `prototype`), where crafted keys write to the object's prototype rather than its own properties.

## What to check
- Does any handler pass the raw request body (`req.body`, `request.POST`, `@RequestBody`, `c.Request.Body`, `params`) straight into a model constructor, ORM update, `Object.assign`, or a spread merge — without first filtering to an allow-list?
- Look for privileged or security-sensitive fields on the bound model: `role`, `isAdmin`, `isStaff`, `emailVerified`, `password`, `passwordHash`, `balance`, `credits`, `tenantId`/`organizationId`, `ownerId`, `price`, `status`, `paidUntil`, `apiKey`, `mfaEnabled`. If any of these are mass-bindable, the finding is high severity.
- For multi-tenant apps: can a client override `tenantId` / `organizationId` to read or write across tenants?
- Is the framework's default binding in use with no `fillable`/`assignable`/`@JsonIgnoreProperties` restriction? (Laravel `Model::create($req->all())`, Spring setter binding, Mongoose `new Model(req.body)`, Rails `update(params[:user])`, Django `ModelForm`, ASP.NET `[Bind]` absent.)
- Are DTOs / "request" structs actually narrower than the persisted entity, or do they mirror it (and therefore leak every setter)?
- Is the language vulnerable to prototype pollution (Node/JS)? Check for `{ ...req.body }`, `Object.assign({}, req.body)`, `lodash.merge`/`_.set` over attacker-controlled paths, and absence of `__proto__`/`constructor` stripping.
- Does a PATCH/PUT "update profile" endpoint accept the same payload shape as the admin "edit user" endpoint?
- Is `JSON.parse` output or `qs` parsed input merged into a config/options object that holds security flags?

## Static signals
Bulk assignment of request body onto a model/object:
- Node: `Object.assign(user, req.body)`, `{ ...user, ...req.body }`, `User.create(req.body)`, `User.updateOne({ id }, req.body)`, `new UserModel(req.body)`, `user.set(req.body)`
- Mongoose: `Model.create(req.body)`, `findByIdAndUpdate(id, req.body)` without a `select`/schema guard; schema fields lacking explicit intent (no `select:false` on secrets)
- Express/EJS: `res.locals.user = { ...req.body }` then persisted
- Sequelize: `User.create(req.body)`, `instance.update(req.body)`
- Laravel/Eloquent: `User::create($request->all())`, `$user->update($request->all())`, `Model::fill($req->post())` — no `$fillable` / `$guarded` on the model
- Rails (Active Record): `User.new(params[:user])`, `@user.update(params[:user])` — no Strong Parameters (`require`/`permit`)
- Django: `ModelForm`, `form.save()`, or `User(**request.POST)` — no `fields = [...]` allow-list on the form / serializer
- Django REST Framework: `class Meta: model = User` with `fields = '__all__'` (or absent `extra_kwargs read_only`)
- Spring/Java: POJO with setters bound from `@RequestBody UserDTO` where DTO mirrors the entity; no `@JsonIgnoreProperties(ignoreUnknown=true)` + no allow-list
- ASP.NET: `[ApiController] public IActionResult Update([FromBody] User u)` with no `[Bind("Name,Email")]` allow-list
- Go: `json.NewDecoder(r.Body).Decode(&user)` then `db.Save(&user)` — no explicit field mapping
- Python (generic): `user.__dict__.update(request.json)`, `setattr(obj, k, v)` in a loop over request keys

Prototype-pollution signals (JS):
- `Object.assign({}, JSON.parse(body))`
- `lodash.merge(obj, req.body)`, `_.set(obj, req.body.path, ...)`
- `extend({}, req.body)` (jQuery/older utils) without `__proto__` filtering

Missing allow-list indicators:
- A model/serializer with `fields = '__all__'`, an empty `$guarded = []`, a DTO whose fields == entity columns, or an absence of `permit`/`require`/`@Bind`/`fields=`/`read_only`/`select:false`.

## False positives
- The handler explicitly picks an allow-list before binding: `pick(req.body, ['name','email'])`, Laravel `$req->only(['name','email'])`, Rails `params.require(:user).permit(:name, :email)`, DRF `fields = ['name','email']`, Spring `[Bind("Name,Email")]`, Go maps fields one-by-one.
- The model has explicit protection: Mongoose schema marks sensitive paths `select:false`/`immutable:true`; Eloquent defines `$fillable` (and `$guarded=['*']`); Spring DTO uses records (immutable, no setters) or `@JsonIgnoreProperties`; JPA entity uses field-level access control.
- The DTO is genuinely narrower than the entity — it declares only the user-settable columns and the controller maps DTO→entity field by field.
- The endpoint is read-only (GET) — mass assignment only applies on state-changing methods (POST/PUT/PATCH).
- Input has already been validated against a strict schema (e.g., Zod/Pydantic with only safe fields) and only those parsed values are forwarded.
- Lodash ≥4.17.20 / modern `Object.assign` mitigate the classic `__proto__` pollution; confirm the version and that `constructor` paths are still rejected.

## Attack scenario
1. The app exposes `PUT /api/users/me` to let users update their profile, implemented as `User.findByIdAndUpdate(req.user.id, req.body, { new: true })` with no allow-list.
2. The attacker (a normal self-registered user) sends `PATCH /api/users/me` with body `{"role":"admin"}` (and optionally `"isVerified":true`, `"tenantId":<victim org>`).
3. The ORM happily assigns `role = 'admin'` because the key exists on the model and nothing filters it.
4. On next request the user's JWT/session now resolves to an admin; they access `/admin/*`, exfiltrate other tenants' data, or grant themselves credits/balance.
5. In a multi-tenant variant, the attacker sets `"tenantId"` to another org and the next list query returns that org's records (broken object-level authorization, amplified by mass assignment).

Prototype-pollution variant: body `{"__proto__":{"isAdmin":true}}` against `Object.assign({}, req.body)` then `if (user.isAdmin)` checks across the app begin returning `true`.

## Impact
- **Confidentiality**: privilege escalation exposes data the user could not otherwise see (admin panels, other tenants).
- **Integrity**: attacker writes privileged fields (`role`, `balance`, `paymentStatus`, `verifiedAt`), corrupting business state and bypassing verification/payment flows. This is the primary impact — mass assignment is usually an **authentication-bypass / privilege-escalation** primitive.
- **Availability**: less common, but overwriting `status`/`quota`/`config` flags can lock users out or trigger error paths.
- Severity scales with which fields are exposed: a writable `role`/`isAdmin` is Critical (authz bypass); a writable `balance`/`price` is High (fraud); a writable cosmetic field is Informational. Prototype pollution is High-to-Critical because it can flip security checks process-wide.

## Remediation
Bind only an explicit allow-list; never persist the raw request body:
```ts
// VULNERABLE — every key on the model is client-writable
app.put('/api/users/me', auth, async (req, res) => {
  const user = await User.findByIdAndUpdate(req.user.id, req.body, { new: true });
  res.json(user);
});

// SAFE — pick exactly the fields the profile endpoint may change
const ALLOWED = ['name', 'email', 'bio'] as const;
app.put('/api/users/me', auth, async (req, res) => {
  const patch = pick(req.body, ALLOWED);            // drop role/isAdmin/tenantId
  const user = await User.findByIdAndUpdate(req.user.id, patch, { new: true });
  res.json(user);
});
```
Equivalent idioms by stack: Rails Strong Parameters (`params.require(:user).permit(:name, :email)`), Laravel `$req->only(['name','email'])` + `$fillable`, DRF `fields = ['name','email']` + `read_only` on sensitive fields, Spring immutable record DTOs with `@JsonIgnoreProperties`, ASP.NET `[Bind("Name,Email")]`, Go one-field-at-a-time mapping, Mongoose schema with `select:false`/`immutable:true` on secrets. **Defense-in-depth:** prefer immutable request DTOs that cannot represent privileged fields at all, enforce object-level authorization server-side (don't trust a client-sent `tenantId`), and strip `__proto__`/`constructor`/`prototype` keys at the JSON-parsing layer in Node.

## References
- OWASP ASVS V5.3.x — Input validation and mass assignment controls
- OWASP WSTG-INPV-12 — Testing for mass assignment / auto-binding
- OWASP Cheat Sheets: Mass Assignment, REST Security, Prototype Pollution
