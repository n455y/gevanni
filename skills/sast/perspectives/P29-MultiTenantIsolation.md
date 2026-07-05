---
id: P29
name: MultiTenantIsolation
area: V8 Authorization
refs: ASVS V4.1.x, V4.3.x / WSTG-ATHZ-04 / CS: Multitenancy, Authorization
requires: [backend]
---

# P29 — MultiTenantIsolation

## Overview
Multi-tenant isolation failures occur when an application that hosts multiple customers, organizations, or workspaces on shared infrastructure fails to enforce a hard boundary between tenant data. A user authenticated for Tenant A can read, modify, or destroy resources belonging to Tenant B. The root cause is almost always a missing or bypassable tenant scoping predicate: a query, ORM call, file lookup, cache key, or background job that trusts a client-supplied `tenantId` (or omits the filter entirely) instead of deriving it from the authenticated session. Defense-in-depth controls — database Row-Level Security (RLS), per-tenant encryption keys, storage prefix isolation — are frequently absent or inconsistently applied, so a single forgotten `WHERE tenant_id = ?` becomes a full cross-tenant breach. This is functionally an IDOR/broken-object-level-authorization (BOLA) problem specialized to the multi-tenant shape.

## What to check
- Does every data-access path (query, ORM lookup, search, cache read, object/file store, message queue consumer) include a tenant scoping predicate, and is that predicate derived from the **session** rather than `req.body.tenantId` / `?tenant=` / a subdomain the client can spoof?
- Is tenant context injected by a single, mandatory middleware/filter that runs on every authenticated route, or is scoping left to each handler (and thus forgotten on some)?
- For direct object references (`/api/docs/:id`), is authorization checked against the *resource's* tenant, not just the requested tenant? I.e., can a user request a UUID from another tenant by parameter-tampering?
- Is tenant switching (`X-Tenant-Id` header, `tenant_id` in body, account-picker UI) validated so a user cannot set it to a tenant they do not belong to?
- Does the data layer enforce isolation at the DB level (PostgreSQL RLS, SQL Server SECURITY POLICY, Firebase rules, document DB partition-key enforcement), or does it rely solely on application code?
- Are bulk/admin endpoints (`/admin/list-all`, export jobs, webhooks, scheduled tasks) scoped to a tenant, or do they return cross-tenant data?
- Are per-tenant resources isolated in shared object storage (S3/GCS) by a validated prefix, with signed URLs scoped to the requester's tenant?
- Are background workers, queue consumers, and cron jobs replaying tenant context, or do they process rows without a tenant filter?
- For secrets/keys (KMS, encryption keys, API credentials), is there per-tenant separation so one tenant's compromise cannot decrypt another's data?

## Static signals
Missing or client-supplied tenant filter:
- Node/Mongoose: `Doc.find({})`, `Doc.findById(id)` with no `tenantId`; `Doc.find({ tenantId: req.body.tenantId })` (client-controlled)
- Node/Prisma: `prisma.doc.findMany()` without `where: { tenantId }`; `prisma.doc.findUnique({ where: { id } })` with no tenant compound key
- Python/Django ORM: `Doc.objects.all()`, `Doc.objects.get(id=...)` without `.filter(tenant=request.user.tenant)`
- Python/SQLAlchemy: `session.query(Doc).all()`, `session.get(Doc, id)` without a tenant filter or `query` event hook
- Rails ActiveRecord: `Doc.all`, `Doc.find(params[:id])` without `current_tenant` scoping (acts_as_tenant / apartment gem absent)
- Java/JPA: `em.createQuery("from Doc")`, `repo.findById(id)` without a `WHERE tenant_id = ?` or Hibernate `@Filter`
- Go: `db.First(&doc, id)`, `db.Find(&docs)` with no `Where("tenant_id = ?", tenantID)`
- PHP/Eloquent: `Doc::all()`, `Doc::find($id)` without a global tenant scope

Client-controlled tenant source:
- `const tenantId = req.headers['x-tenant-id']`
- `tenantId = request.json.get('tenant_id')` / `request.args.get('tenant')`
- `const { tenantId } = req.body; ... Doc.find({ tenantId })`
- Subdomain-derived without validation: `const tenant = req.hostname.split('.')[0]`

DB-level isolation absent:
- No `ROW LEVEL SECURITY` / `FORCE ROW LEVEL SECURITY` policy in migrations (PostgreSQL)
- No SQL Server `SECURITY POLICY` / `FILTER PREDICATE`
- Firebase/Firestore security rules without `request.auth.token.tenantId == resource.data.tenantId`
- Shared cache key without tenant: `cache.get('user:' + id)` (collides across tenants)

## False positives
- A single-tenant deployment (one customer per instance) — tenant scoping is moot, though confirm the codebase is not also sold as multi-tenant SaaS.
- DB RLS / a global ORM scope (Django manager, Rails `default_scope`, Prisma extension, Hibernate `@Filter`) is consistently applied and verified active for every connection, with no `bypassrls` superuser used by the app role.
- The endpoint is intentionally cross-tenant and gated by a strong global-admin role check (`isPlatformAdmin &&`) verified server-side — not just a missing filter.
- Tenant isolation is enforced at the storage layer (separate database/schema/bucket per tenant, selected by connection routing) rather than in query predicates.
- The `tenantId` comes from a verified JWT claim set by the IdP, not from a client-controllable request field, and the claim is re-validated on each request.

## Attack scenario
1. Attacker signs up for the SaaS as Tenant A and captures their own `tenantId` and a valid session token.
2. They observe a detail endpoint: `GET /api/invoices/{id}`. The handler does `Invoice.findById(id)` with no tenant predicate.
3. Attacker enumerates or guesses UUIDs / sequential IDs of Tenant B's invoices (via leaked links, predictable formats, or brute force on integer IDs).
4. `GET /api/invoices/<tenantB-uuid>` with Tenant A's session returns Tenant B's invoice data — a direct cross-tenant read.
5. Escalation: if the same `findById` pattern exists on write paths (`PUT`, `DELETE`), the attacker mutates or destroys Tenant B's records. If export/search endpoints lack the filter, they bulk-exfiltrate entire tenants.

## Impact
- **Confidentiality**: full cross-tenant data disclosure — every other tenant's records, PII, financials, and documents become readable.
- **Integrity**: unauthorized modification/deletion of other tenants' data; cross-tenant poisoning of shared indexes, reports, or AI training pipelines.
- **Availability**: destructive deletes or lockout of adjacent tenants; mass data loss.
- Severity is typically **Critical**: one missing predicate exposes *all* tenants, not one record. Blast radius scales with tenant count and data sensitivity; in regulated industries (healthcare, finance) this triggers statutory breach notification.

## Remediation
Derive the tenant from the authenticated session, never from a client-controlled field, and scope every query through it:
```ts
// VULNERABLE — no tenant predicate; cross-tenant IDOR
app.get('/api/invoices/:id', auth, async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);
  res.json(invoice);
});

// SAFE — tenant derived from session, applied as a compound key
app.get('/api/invoices/:id', auth, async (req, res) => {
  const tenantId = req.user.tenantId;          // from verified JWT/session
  const invoice = await Invoice.findOne({
    _id: req.params.id,
    tenantId,                                   // hard tenant scoping
  });
  if (!invoice) return res.status(404).end();
  res.json(invoice);
});
```
Layer database Row-Level Security (PostgreSQL RLS / SQL Server SECURITY POLICY / Firestore rules bound to the auth token's `tenantId`) beneath the app so a forgotten filter fails closed rather than leaking data. Disable `BYPASSRLS` on the application DB role, and give every background worker an explicit tenant context.

## References
- ASVS V4.1.x, V4.3.x
- WSTG-ATHZ-04
- CS: Multitenancy, Authorization
