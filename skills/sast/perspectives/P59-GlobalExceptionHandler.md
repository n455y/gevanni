---
id: P59
name: GlobalExceptionHandler
area: V16 Security Logging and Error Handling
refs: ASVS V7.x / WSTG-ERRH-01 / CS: Error Handling
---

# P59 — GlobalExceptionHandler

## Overview
An unhandled exception or rejected promise propagates past the request boundary with no centralized handler to catch it. The consequences are twofold: (1) the worker process crashes, the request hangs until a socket timeout, or the server returns a default stack trace — leaking internal paths, SQL fragments, framework versions, and environment details; and (2) missing `process.on('unhandledRejection' | 'uncaughtException')` hooks let one bad request take down the entire Node/Deno process. The root cause is always a missing error boundary: no Express 4-arg error middleware, no Fastify `setErrorHandler`, no Nest `ExceptionFilter`, no async wrapper for promise-returning route handlers, and no process-level backstop. A single `throw` in an unwrapped async handler is enough to destabilize a service.

## What to check
- Is there a framework-level error boundary registered last in the pipeline (Express 4-arg `(err, req, res, next)`, Fastify `setErrorHandler`, Nest global `ExceptionFilter`, ASP.NET `UseExceptionHandler`, Django `handler500`, Rails `rescue_from`, Spring `@ControllerAdvice`/`@ExceptionHandler`)?
- Do async route handlers propagate rejections to that boundary — via `express-async-handler`, an async wrapper, or a framework that awaits for you (Fastify, Nest, Koa, Express 5)? In Express 4 a thrown/rejected promise is NOT caught by the error middleware.
- Are `process.on('unhandledRejection')` and `process.on('uncaughtException')` defined? Does the latter trigger a graceful shutdown (finish in-flight, close server, `process.exit(1)`) rather than silently continuing in a corrupt state?
- Are default error pages / stack traces disabled in production (`NODE_ENV=production`, `app.debug=false`, `DEBUG=False`, `displayErrorDetails=false`)?
- Does the error response leak internals — raw `err.message`, `err.stack`, ORM/SQL errors, file paths, header dumps — to the client?
- Are errors written to an audit log with correlation IDs, and is sensitive data (passwords, tokens, PII) scrubbed before logging?
- Do background workers, queues (BullMQ, Celery), and schedulers have their own try/catch or dead-letter handling, or does one job poison the worker?

## Static signals
Missing or weak error boundary:
- Express 4 with NO 4-arg middleware: `app.use((req, res, next) => ...)` registered but no `app.use((err, req, res, next) => ...)`.
- Async handler without wrapper: `app.get('/x', async (req, res) => { await risky(); })` — a rejection here is never caught by Express 4's error middleware.
- Missing process hooks: no `process.on('unhandledRejection' ...)` / `process.on('uncaughtException' ...)` in the entrypoint.
- Fastify: no `app.setErrorHandler(handler)` registered.
- NestJS: no `@Catch()` / `ExceptionFilter` bound via `app.useGlobalFilters(...)`; no `HttpException` mapping for business errors.
- Koa: no outer `app.use(async (ctx, next) => { try { await next() } catch (e) {...} })`.
- Python: bare `except:` that swallows errors silently, or no `try/except` in view functions; Flask/Django without a 500 handler.
- Java/Spring: exception escaping a controller with no `@ControllerAdvice`; default Whitelabel Error Page enabled.
- Go: `panic` inside an HTTP handler with no `defer recover()` in middleware.

Information leakage in error responses:
- `res.status(500).send(err.stack)` / `res.json({ error: err })` / `return next(err.message)`
- `console.error(err)` written but also `err.stack` echoed in the response body.
- Returning ORM errors verbatim: `res.status(500).json({ error: e.message })` where `e` is a Sequelize/Prisma error containing the offending SQL/row.

## False positives
- Express 5+, Fastify, NestJS, Koa, and Hapi automatically forward async rejections to the error handler — an explicit async wrapper is not required there (verify the framework version).
- The app uses `express-async-handler` (or an equivalent wrapper) consistently, AND the 4-arg error middleware returns a generic message and logs the detail server-side — this is the correct pattern.
- `uncaughtException` logs the error and calls `process.exit(1)` after draining connections — that is a deliberate graceful-shutdown design, not a missing handler.
- The endpoint is behind a framework whose default error page is disabled in production and replaced by a sanitized JSON shape (Spring `server.error.include-stacktrace=never`, ASP.NET `UseExceptionHandler("/error")`).
- A background worker explicitly retries/dead-letters failures; an unhandled rejection in that context is contained.

## Attack scenario
1. The attacker sends a malformed request that triggers an exception in an async Express 4 handler lacking a wrapper and a registered error middleware: `POST /api/order { "qty": "abc" }`.
2. The thrown/rejected promise is never caught. Express 4 leaves the socket open; the default behavior returns `Cannot POST /api/order` or, if a catch-all returns `err.stack`, the full stack with file paths, framework version, and a Prisma error disclosing the `Order` table schema.
3. The leaked internals let the attacker fingerprint the stack and craft follow-on injection. If multiple handlers share the defect, the attacker replays the request in a loop.
4. Without `uncaughtRejection`/`uncaughtException` handlers, repeated malformed requests exhaust or crash worker processes, degrading availability for all tenants.

## Impact
- **Confidentiality**: stack traces, internal paths, dependency versions, DB schema, and partial query results disclosed to the caller.
- **Integrity**: a crashed mid-flight request may leave transactions half-applied if idempotency/rollback is missing.
- **Availability**: a single unhandled rejection in Node can kill the process; under Express 4 it can hang connections until socket timeout. Repeatable triggers enable a low-effort DoS.
- Severity scales with statefulness and privilege: a crash mid-transaction in an admin flow can corrupt shared state and amplify into a full outage.

## Remediation
Register a centralized boundary, wrap async handlers, and add process-level backstops that never echo internals:
```ts
// VULNERABLE — async rejection escapes Express 4, no error middleware, no process hooks
app.get('/x', async (req, res) => { await risky(req.query.id); });
// a rejection hangs the socket or crashes the process; default pages leak internals

// SAFE — async wrapper + 4-arg error middleware + process backstops
import asyncHandler from 'express-async-handler';

app.get('/x', asyncHandler(async (req, res) => {
  const r = await risky(req.query.id);   // rejection now forwarded to the error middleware
  res.json(r);
}));

// registered LAST, after all routes and other middleware
app.use((err, req, res, next) => {
  req.log.error({ err, path: req.path }, 'unhandled error');   // detail server-side only
  res.status(err.status || 500).json({ error: 'internal_error' }); // generic to client
});

process.on('unhandledRejection', (reason) => { req.log.error({ reason }, 'unhandledRejection'); });
process.on('uncaughtException', (err) => {
  req.log.error({ err }, 'uncaughtException — shutting down');
  server.close(() => process.exit(1));
});
```
As defense-in-depth: disable stack traces in production (`NODE_ENV=production`, Spring `include-stacktrace=never`, ASP.NET `UseExceptionHandler`), return a fixed error contract to clients, scrub secrets from logs, and wrap background jobs with retry/dead-letter so one failure cannot poison the worker.

## References
- OWASP ASVS V7.x — Error handling and logging; V7.4.x — logging security requirements
- OWASP WSTG-ERRH-01 — Testing for Improper Error Handling
- OWASP Cheat Sheet: Error Handling
