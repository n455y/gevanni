---
id: P94
name: RESTExposureMassAssignment
area: V4 API and Web Service
refs: ASVS V13.x / WSTG-ATHZ-03, WSTG-INPV-12 / CS: REST Security, Mass Assignment (OWASP API3:2023 - Broken Object Property Level Authorization)
requires: [backend]
---

# P94 — REST Exposure / Mass Assignment

## Overview
This perspective covers two related REST API design flaws, both stemming from **missing property-level authorization**: *Excessive Data Exposure* (the API returns more fields than the client needs, leaking sensitive attributes such as `role`, `tenantId`, `passwordHash`, or `apiKey`) and *Mass Assignment* (the API binds client-supplied input directly onto the domain model, letting a caller overwrite fields they were never meant to set — most dangerously `role`, `isAdmin`, `balance`, or `tenantId`). The root cause is identical in both cases: the framework's default object (de)serialization is trusted blindly, and no allow-list gates which properties may leave or enter the object. Because the request looks syntactically valid, neither the schema validator nor the business rule layer rejects it — the attacker simply adds an extra JSON key. These are the API-side facets of P70-ExcessiveDataExposure and P50-MassAssignment; this view focuses on REST/JSON handlers specifically.

## What to check
- Does any handler return the raw ORM/entity object (`res.json(user)`, `return entity`) instead of a filtered DTO? Trace whether `passwordHash`, `secret`, `role`, `tenantId`, `mfaSecret`, `apiKey`, `resetToken`, or PII fields are reachable in the serialized payload.
- Is request input (`req.body`, `@RequestBody`, `request.json()`, `params`) bound wholesale onto the model via `Object.assign`, spread/merge, `model.update(req.body)`, `update_attributes`, `setattr`, or framework auto-binding (`@ModelAttribute`, Spring `@RequestBody` mapped to the entity, Rails `update(params)`, Laravel `fill($request->all())`)?
- Are input and output field sets governed by an explicit allow-list / DTO, or does the framework serialize "everything not explicitly hidden"?
- Does the same payload shape get returned regardless of the caller's role (anonymous / regular user / admin)? Sensitive fields must be redacted per-role, not per-endpoint only.
- Does the OpenAPI/schema declaration match the actual wire response? A response containing extra fields the schema omits is a strong exposure smell.
- For multi-tenant APIs, can a caller set or read `tenantId` / `organizationId` / `ownerId` and thereby cross tenant boundaries (horizontal escalation)?
- Are "hidden" framework annotations actually applied? `@JsonIgnore`/`@JsonProperty(access = WRITE_ONLY)`/`password_digest` excludes only fire if present on the entity being serialized, not on a parent class.

## Static signals
Whole-object binding (mass assignment):
- Node/Express: `Object.assign(user, req.body)`, `await User.update(req.body)`, `Object.assign(doc, req.body, { overwrite: true })`, `user.set(req.body)`
- Prisma/Sequelize/Mongoose: `await prisma.user.update({ where:{id}, data: req.body })`, `await User.update(req.body)`, `doc.set(req.body); doc.save()`
- Python (Django/FastAPI/Flask): `User.objects.filter(...).update(**request.data)`, `model_instance = User(**body)`, `setattr(user, k, v)`, Pydantic `model.model_validate(body)` then `.save()`
- Java/Spring: `public ResponseEntity put(@RequestBody UserEntity user)` (binding directly to the entity rather than a DTO), `BeanUtils.copyProperties(src, entity)`
- Ruby/Rails: `User.update(params[:user])`, `user.assign_attributes(params)`, `user.update!(params.require(:user).permit!)` (the `permit!` defeats strong params)
- Laravel: `User::create($request->all())`, `$user->fill($request->all())->save()`, `$request->all()` with no `$fillable` allow-list
- Go: `json.NewDecoder(req.Body).Decode(&user)` then `db.Save(&user)`

Excessive exposure (serialization):
- `res.json(user)` / `res.send(user)` where `user` is the ORM entity, not a DTO
- `return this.repo.findOne(id)` (Spring Data) returned straight to the controller
- Serializer with no `fields = [...]` allow-list: DRF `ModelSerializer` without `fields`; Rails `as_json` without `only:`; Jackson with no `@JsonIgnoreProperties`

Signs of adequate protection (confirm before downgrading):
- Explicit allow-list: `pick(req.body, ['name','email'])`, `body('role').not().exists()`, Spring `@JsonIgnoreProperties` / DTO mapping, Rails strong params `params.require(:user).permit(:name, :email)`, Laravel `$fillable`/`$guarded`, DRF `fields = ('id','email')`.

## False positives
- A dedicated DTO/response object with an explicit field allow-list is used, and the entity's secret fields are never reachable from it. Confirm the DTO is the only object serialized.
- Input is validated by a strict schema (zod / Pydantic `extra='forbid'` / class-validator with whitelist / JSON Schema `additionalProperties: false`) that rejects unknown keys before they reach the model.
- Framework-level mass-assignment protection is genuinely active and not bypassed: Rails strong params without `permit!`, Laravel `$fillable` listing only safe attributes, Jackson `@JsonIgnoreProperties(ignoreUnknown = true)` plus `FAIL_ON_UNKNOWN_PROPERTIES`, Django's `update_fields=[...]`.
- The handler returns only a status code or a scalar (token string, count) — no object graph.
- The entity genuinely has no sensitive fields (a pure lookup table of public reference data).

## Attack scenario
1. The API exposes `PUT /api/v1/users/me` accepting a JSON body to update profile fields (`name`, `email`); the handler does `await User.update(req.body, { where:{ id:req.user.id } })`.
2. Attacker (a regular, authenticated user) sends `{"name":"x","role":"admin"}`.
3. The ORM binds every key, including `role`, onto the row — there is no allow-list.
4. The attacker re-logs in (or even on the same session) and now has administrative privileges, reading other users' data and performing privileged actions.
5. A parallel exposure attack: `GET /api/v1/users/me` returns `res.json(user)`. The attacker reads their own profile and finds `passwordHash`, `mfaSecret`, `tenantId`, and `apiKey` in the payload — credentials to forge or pivot into another tenant by replaying `tenantId` in a later request.

## Impact
- **Confidentiality**: full leakage of credentials, tokens, PII, and cross-tenant data via over-broad responses.
- **Integrity**: arbitrary privilege escalation (`role`/`isAdmin`), account takeover, financial manipulation (`balance`/`credits`), tenant boundary crossing.
- **Availability**: limited direct impact, but a self-granted admin can disable/lock out other users and reconfigure the system.
- Severity scales with the binding surface: a model exposing `role` or `tenantId` to mass assignment is typically **Critical**; exposure-only (read of secrets) is **High**; exposure of non-sensitive PII is **Medium**.

## Remediation
Never bind input directly to the persistence model; map through a validated DTO with an explicit property allow-list, and serialize a separate response DTO.
```ts
// VULNERABLE — whole-body bind onto the entity, full object returned
router.put('/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  Object.assign(user, req.body);           // attacker sets role/tenantId
  await user.save();
  return res.json(user);                    // passwordHash/role leak out
});

// SAFE — allow-listed patch + role-scoped response DTO
const SAFE_FIELDS = ['name', 'email'] as const;
router.put('/users/:id', async (req, res) => {
  const patch = pick(req.body, SAFE_FIELDS);            // unknown keys dropped
  const user = await User.update(patch, { where: { id: req.params.id } });
  return res.json(toPublicUserDTO(user));               // only id/name/email
});
```
Defense-in-depth: reject unknown keys at the schema layer (`z.object({...}).strict()` / Pydantic `extra='forbid'` / JSON Schema `additionalProperties:false`), annotate secret entity fields as write-only/ignore (`@JsonIgnore`, `password: never` on the response type), and run automated contract tests that assert the OpenAPI response schema equals the actual payload so new secret fields can't silently leak.

## References
- OWASP ASVS V13.x — API and Web Service protection (input/output schema validation, sensitive data exposure)
- OWASP API Security Top 10 2023 — API3: Broken Object Property Level Authorization (excessive data exposure + mass assignment)
- OWASP WSTG-ATHZ-03 — Testing for Bypassing Authorization Schema; WSTG-INPV-12 — Testing for Mass Assignment
- OWASP Cheat Sheets: REST Security, Mass Assignment
