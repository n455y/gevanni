---
id: P95
name: RESTRateLimit
refs: ASVS V13.4.x / WSTG-ATHN-04 / CS: REST Security, Denial of Service — OWASP API4:2023 Unrestricted Consumption
---

# P95 — REST Rate Limit

## Preconditions

The code exposes an API.


## Overview
Unrestricted resource consumption occurs when a REST/HTTP API imposes **no effective limit** on how often, how concurrently, or how heavily a client can invoke it — letting a single caller (or a distributed botnet) exhaust CPU, memory, DB connections, third-party quota, or egress bandwidth and drive the service into denial-of-service or runaway billing. OWASP API Top 10 (2023) ranks this **API4: Unrestricted Consumption**. The root cause is not a missing crypto primitive but a missing *operational* control: endpoints that do real work — authentication, search, aggregation, export, file upload/processing, ML inference, or third-party API fan-out — are exposed without a per-user/per-IP/per-tenant rate limit, a concurrency cap, a page-size ceiling, or a per-request cost timeout. Rate limiting must be applied at the right granularity (account or token, not only IP, which is trivially spoofed behind NAT/proxies) and combined with pagination caps and backpressure to actually bound worst-case cost.

## What to check
- Is there a **rate limit** on every non-trivial endpoint — expressed per authenticated user/API key per window, and (for unauthenticated endpoints) per source IP? Confirm the key is not spoofable (authenticated principal > IP > X-Forwarded-For).
- Are the most expensive endpoints — login/OTP/verify, password reset, search, aggregation/group-by, export/report generation, file upload/transcode, third-party API fan-out, LLM calls — covered by **both** a request-rate limit and a **concurrency / cost / timeout** limit?
- Is `?limit=` / `?page_size=` / `?count=` / GraphQL `first:` **clamped server-side** to a maximum? Is there a hard cap on returned rows independent of the client-provided value?
- Are long-running operations (export, batch, sync) **queued behind a job system** with a per-user concurrency limit rather than executed synchronously in the request path?
- Do uploads/downloads bound **payload size** (`Content-Length` cap, streaming size check, multipart field limits) and **execution time** (DB `statement_timeout`, request `timeout`)?
- For third-party (paid) API calls or LLM invocations, is there a **monthly/tenant quota** and overage alert, so abuse cannot create unlimited provider charges?
- Does the limiter run **before** expensive work (auth resolved, DB query planned), not after the response is already built? A limit checked only at the controller end is useless against a heavy ORM query.
- Is the limiter state stored in a **shared** store (Redis/memcached/DB) shared across all instances, so horizontal scaling does not multiply the effective limit?
- Are `429 Too Many Requests` responses emitted with `Retry-After`, and is there a jittered backoff on the client side? (Avoids synchronized retry storms.)
- For GraphQL: are **query depth**, **query complexity/cost**, **aliasing/batching**, and persisted-query allow-lists enforced? (A single GraphQL POST can fan out into thousands of DB calls.)
- Are there separate, **stricter** limits on authentication endpoints (login, OTP, password reset, MFA verify) to prevent brute-force / credential-stuffing / OTP enumeration (also see P* AuthN)?

## Static signals
No rate-limit middleware/function applied at all:
- Node/Express: routes/handlers with no `rateLimit`, `express-rate-limit`, `@nestjs/throttler`, `apollo-server` cost plugin, or upstream gateway rule; `app.get('/api/search', handler)` with nothing in between.
- Python: Django REST Framework without `throttle_classes`; Flask routes without `Flask-Limiter`/`@limiter.limit`; FastAPI without `slowapi` `@limiter.limit` or a gateway rule.
- Java/Spring: `@RestController` methods without `@RateLimiter` (Resilience4j/Bucket4j) and no `spring-cloud-gateway` `RequestRateLimiter` filter.
- Go: `http.HandleFunc` / `mux.HandleFunc` with no `golang.org/x/time/rate` limiter, tollbooth, or chi middleware.
- Ruby/Rails: controllers without `rack-attack`/`rack-throttle` and no Rails `rate_limit` on routes.
- PHP/Laravel: routes without `throttle:` middleware (`Route::get(...)->middleware('throttle:60,1')`).

Unbounded / client-controlled page size or cost:
- `prisma.model.findMany({ take: req.query.limit })` — take is client-controlled, unclamped.
- `Model.objects.all()[:req.GET['limit']]` / `Model.query.paginate(page, per_page=...)` with no `min(limit, MAX)`.
- `db.collection.find().limit(parseInt(req.query.limit))` (MongoDB) — negative or huge values.
- SQL: `LIMIT $1` with the bound parameter taken directly from the request.
- GraphQL: schema without `@cost`/`@complexity` directives and resolver without depth-limit / cost-analysis (`graphql-cost-analysis`, `graphql-depth-limit`, Apollo `costAnalysis`).

Heavy work executed synchronously / without timeout:
- `await Export.generate(user, 'all')` directly in the request handler (no queue, no cap on concurrent exports).
- `Search.es.search({ size: 999999 })` / aggregations over the full index per request.
- LLM/third-party calls `await openai.chat.completions.create(...)` with no per-user quota or timeout.
- DB calls with no `statement_timeout` / `SET LOCK_TIMEOUT` / query timeout.

Concurrency / resource exhaustion patterns:
- Unlimited file uploads: no `maxFileSize`, no `multer({ limits: { fileSize } })`, no streaming size guard — memory exhaustion via huge multipart bodies.
- Endless streaming endpoints (`text/event-stream`, WebSocket) without per-connection caps — connection-flood DoS.
- Login/OTP loops without per-identifier throttle: `verifyOtp(code)` called in a loop with no `>= N attempts → lockout`.

Limiter scoped to a spoofable key:
- `keyGenerator: (req) => req.ip` relying on `X-Forwarded-For` directly when the app sits behind a proxy that does not overwrite it (`app.set('trust proxy', ...)` misconfigured).
- Limiter keyed only on IP for an authenticated API (should key on user/token).

## False positives
- A **per-user/per-IP/per-tenant rate limit + concurrency cap + page-size clamp** is in place and the limiter runs before the expensive work. Confirm the limit is enforced at the right scope (authenticated principal, not only IP) and shared across instances.
- The endpoint is gated by an upstream **API gateway / WAF / load balancer** (Cloudflare, AWS WAF, Kong, Apigee, Envoy) that applies rate limiting and request-size limits, with the backend reachable only through it.
- The route is **internal-only** (mTLS service mesh, private VPC, no public ingress) and its callers are trusted services with their own governance.
- Expensive work is queued through a **bounded job system** (Celery/Sidekiq/SQS with concurrency limits, BullMQ with `limiter`), so request rate does not translate into unbounded resource use.
- Per-tenant **quota and billing-alert** monitoring catches anomalies for paid/LLM calls (this is detection, not prevention — downgrade severity, do not treat as fully resolved).
- The endpoint is cheap and idempotent (a status read from cache) and the platform already caps RPS globally.

## Attack scenario
1. The attacker registers (or uses anonymous access to) a public API that has no per-user limit and no page-size cap, e.g. `GET /api/search?q=*&limit=99999999`.
2. They script a loop (or a small botnet / `ab` / `wrk` / distributed curl) issuing thousands of concurrent requests, each asking for the maximum page size or a wildcard search that triggers a full-table scan / large aggregation.
3. Each request holds a DB connection, allocates large result buffers, and saturates CPU and memory; the connection pool is exhausted and the database begins queueing or timing out.
4. Legitimate users see `502`/`503`/timeouts — denial of service. Meanwhile a third-party or LLM-backed endpoint accrues provider charges proportional to request volume, producing a massive bill (financial DoS / fraud).
5. If the same gap exists on `/login` or `/verify-otp`, the attacker pivots to credential stuffing or OTP enumeration at unlimited speed.

## Impact
- **Availability**: primary impact — full service outage via connection/CPU/memory exhaustion; degraded latency for all tenants (noisy-neighbor effect).
- **Confidentiality**: mass automated probing (login brute-force, OTP enumeration, IDOR enumeration) becomes feasible, indirectly leaking accounts/data.
- **Integrity**: abuse of state-changing endpoints (mass account creation, vote/like manipulation, bulk data modification).
- **Severity** scales with endpoint cost and blast radius: a cheap cached read with a global gateway cap is Low; an unauthenticated search/export/LLM endpoint with no limit on a multi-tenant system is **High/Critical** (outage + financial loss). Multi-tenant platforms must prevent one tenant from starving the others.

## Remediation
Apply per-principal rate limiting and clamp all client-controlled sizing inputs server-side:
```ts
// VULNERABLE — no rate limit, client-controlled page size, heavy work inline
app.get('/api/search', async (req, res) => {
  const rows = await Search.run(req.query.q, Number(req.query.limit)); // limit=99999999
  res.json(rows);
});

// SAFE — rate limit + clamped page size + timeout
import rateLimit from 'express-rate-limit';

const searchLimiter = rateLimit({
  windowMs: 60_000, max: 30,
  keyGenerator: (req) => req.user?.id ?? req.ip,   // principal first, IP fallback
  standardHeaders: true, legacyHeaders: false,
});

app.get('/api/search', searchLimiter, async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 50);   // hard cap
  const rows = await Search.run(req.query.q, limit, { timeoutMs: 2000 });
  res.json(rows);
});
```
Defense-in-depth: enforce request-rate AND concurrency/cost limits at the gateway, page-size AND depth/complexity limits in the app, `statement_timeout` on the DB, per-tenant quotas on paid/LLM calls, and jittered `429` + `Retry-After` so clients back off smoothly. Prefer authenticating the caller and keying the limiter on the principal rather than on (spoofable) IP alone.

## References
- OWASP ASVS V13.4.x — Web Service / RESTful web service protection (rate limiting, resource consumption)
- OWASP WSTG-ATHN-04 — Testing for Bypassing Authentication Schema (lockout / brute-force rate limits)
- OWASP Cheat Sheets: REST Security, Denial of Service, GraphQL Security (query cost/depth)
- OWASP API Security Top 10 (2023) — API4:2023 Unrestricted Resource Consumption
