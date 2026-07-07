---
id: P2
name: LayerSeparation
refs: ASVS V1.x / WSTG-INFO-02 / CS: Architecture Cheat Sheet
---

# P2 — LayerSeparation

## Preconditions

The code has internal architecture or layers.


## Overview
Layer separation is the architectural principle that presentation (router/controller), business logic, and data-access layers must be kept distinct, with input validation and security controls (authentication, authorization, output encoding) applied consistently **at each boundary**. When concerns bleed across layers — a route handler that runs raw SQL, a controller that skips authorization because "the model handles it", or business rules (price/quantity/discount calculations) scattered into client code — security checks become easy to miss on the path of least resistance. The root cause is rarely a single bug; it is an architectural smell where a developer adding a new endpoint can bypass the established control plane by writing one line directly against the database or ORM. Such lapses produce authorization bypasses, injection, and logic flaws that per-layer review would have caught.

## What to check
- Are presentation (HTTP/router/controller), business-logic (service/use-case), and data-access (repository/ORM/model) layers genuinely separated, or do handlers reach directly into the database?
- Does any route/controller contain raw SQL, query-builder calls, or ORM calls inline (`db.query(...)`, `prisma.user.findMany(...)`, `User.where(...)`) instead of delegating to a repository/service?
- Are authorization checks enforced in middleware or the controller, or are they pushed entirely into the model layer (hooks/scopes) such that a new caller can silently bypass them?
- Does the **same** security control (auth, authz, validation, rate-limit) get applied on every entry point, or do some routes (e.g. internal APIs, GraphQL resolvers, background-job handlers, WebSocket events) skip it?
- Are business rules that affect security (max transfer amount, allowed roles, price computation, quota) computed server-side in a single authoritative place, or duplicated/trusted from the client?
- Is input validation centralized (DTO/schema validation at the boundary) or scattered ad-hoc per handler?
- Do shared utility/repository functions perform their own authorization, or do they trust any caller (the "confused deputy")?
- Are there admin/internal endpoints that bypass the layered controls intended for public routes?

## Static signals
SQL/query-builder calls inside route handlers or controllers:
- Node/Express: `app.get('/x', (req,res) => db.query(\`SELECT ... ${req.params.id}\`))`
- Node/Sequelize/Prisma inside a controller: `const u = await prisma.user.findUnique({ where: { id: req.params.id } })`
- Python/Django: a view calling `User.objects.raw(f"SELECT ... {id}")` or `cursor.execute(... % id)` instead of a service/manager
- Python/FastAPI: route bodies doing `session.query(User).filter(...)` directly
- Java/Spring: `@RestController` methods invoking `jdbcTemplate.queryForObject("... " + id)` or `entityManager.createNativeQuery(...)`
- Go: `http.HandleFunc` closures calling `db.Query("SELECT ... " + r.URL.Query().Get("id"))`
- PHP/Laravel: route closures with `DB::select("SELECT ... " . $id)` instead of Eloquent/API controller
- Ruby/Rails: controller actions with `User.find_by_sql("... #{params[:id]}")` instead of a service object

Authorization pushed only into the model / missing at the controller:
- Controllers that fetch and return a resource without an ownership/authorization check: `return repo.findById(req.params.id)`
- Rails: reliance solely on model-level `default_scope` instead of `authorize!`/Pundit in the controller
- Django: no `get_object_or_404(..., owner=request.user)` filter; trust that a manager scopes results
- Spring: `@PreAuthorize` absent on public `@RequestMapping` methods
- A repository/service exposing generic `findAll()`/`getById()` with no tenant/user scoping, callable from any caller

Business logic leaking to client/un-layered:
- Price/total/role sent from the client and stored unchecked: `order.total = req.body.total`
- Discount or interest computed in front-end JS and trusted server-side
- Duplicate validation: same rule coded differently in client, controller, and DB with drift

## False positives
- Small, intentionally monolithic apps or prototypes where collapsing layers is a documented design decision — lower severity, but still note for production growth.
- The model/hook layer (e.g. Rails callbacks, Django signals, ORM scopes) **consistently and unavoidably** enforces authorization/validation such that no caller — internal API, job, or new route — can bypass it. Verify there is no unguarded entry point before treating as protected.
- Read-only/immutable repository methods whose results are always re-filtered by the controller's authorization layer.
- A legacy "thin controller, fat model" codebase that is being migrated; flag the gap rather than asserting a new vulnerability.

## Attack scenario
1. The application follows a layered design: most routes use an `authz` middleware and a `userService` that scopes queries to the caller's tenant.
2. A developer adds a "quick" internal endpoint that reaches directly into the ORM, skipping both: `app.get('/admin/users/:id', (req,res) => User.findById(req.params.id))`.
3. The endpoint is exposed on the public router (mis-classified or never gated), so an attacker learns of it via a JS bundle or API-doc leak.
4. Attacker sends `GET /admin/users/123` with their own session — no authorization runs, and the model returns any user by raw id.
5. The attacker enumerates all tenant users, pivots to horizontal privilege escalation, or exfiltrates data the layered path would have hidden.

## Impact
- **Confidentiality**: cross-tenant data exposure when data-access calls bypass per-user scoping.
- **Integrity**: unauthorized writes/updates when business rules are not enforced at the authoritative layer; price/quantity/role tampering when logic is client-trusted.
- **Availability**: administrative endpoints reached without authorization can be abused for mass deletion or resource exhaustion.
- Severity scales with which control is bypassed: skipped authz on a read is often High; skipped authz plus a write, or injection from concatenated SQL in the controller, can be Critical.

## Remediation
Enforce controls at layer boundaries; never let a route talk to the database directly:
```ts
// VULNERABLE — raw SQL + no authorization inside the route
app.get('/users/:id', (req, res) =>
  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)
    .then(([u]) => res.json(u))
);

// SAFE — middleware authz, delegated service layer, parameterized data access
app.get('/users/:id', authenticate, authz('user:read'), (req, res) =>
  userService.getForCaller(req.params.id, req.user)  // scopes by tenant/owner
    .then((u) => res.json(u))
);
```
Apply defense-in-depth: validate input at the boundary (schema/DTO), authorize in middleware and again in the service when crossing trust boundaries, parameterize every query, and compute security-relevant business rules server-side in one authoritative place.

## References
- OWASP ASVS V1.x — Architecture, separation of layers and centralized controls
- OWASP WSTG-INFO-02 — Fingerprinting / understanding application architecture
- OWASP Cheat Sheets: Architecture, Application Security Architecture
