---
id: P58
name: StackTraceExposure
area: V16 Security Logging and Error Handling
refs: ASVS V7.x / V14.x / WSTG-ERRH-01 / CS: Error Handling
requires: []
---

# P58 — StackTraceExposure

## Overview
Stack-trace and verbose-error exposure happens when an application returns internal failure detail — exception stack traces, absolute filesystem paths, SQL fragments, framework/version banners, or environment variables — to the client instead of a generic, sanitized error. The root cause is almost always an error handler that serializes the raw exception object (`err`, `err.stack`, `e.message`, `str(e)`, `printStackTrace()`) straight into the HTTP response body, or a missing global error handler that lets the framework's default debug page (Spring Boot Whitelabel, Django debug, Play Framework, ASP.NET Yellow Screen of Death, PHP Whoops, Laravel `APP_DEBUG=true`) render in production. This is an information-disclosure weakness (ASVS V7.4 / V14.4): while not a direct pre-auth exploit, it gives attackers a reconnaissance shortcut — technology stack, library versions, internal class structure, and file layout — that sharply lowers the cost of follow-on attacks.

## What to check
- Does the production error path (global handler or per-route `try/catch`) ever serialize the raw exception object, `err.stack`, `err.message`, `e.getStackTrace()`, or `traceback.format_exc()` into the response body or headers?
- Is a generic, opaque error returned to clients (`500 Internal Error` with a correlation/trace ID) while full detail is written only to server-side logs?
- Are debug developer pages enabled in production — Express `NODE_ENV` unset or not `production`; Django `DEBUG=True`; Laravel `APP_DEBUG=true`; Spring Boot `server.error.include-stacktrace=always`; ASP.NET `<customErrors mode="Off"/>`; Play in dev mode; PHP `display_errors=On` / Whoops enabled?
- Do 404 / 405 / 500 pages leak the resolved absolute path (`/var/www/app/...`), the framework banner (`Apache/2.4.41`, `Express/4.17.1`), or the server's IP/internal hostname?
- Does an error response echo the failing SQL query, ORM driver message (e.g. PostgreSQL constraint name, MongoDB `$where`), or DB connection string?
- Are unhandled-rejection / uncaught-exception handlers (`process.on('uncaughtException')`, `EventEmitter` error listeners) wiring the error into a response rather than logging and exiting?
- Do GraphQL endpoints return `errors[].extensions.exception.stacktrace` (Apollo `formatError` not overridden) in production?
- Is stack-trace detail turned on conditionally but the production-detection guard itself is wrong (e.g. checked against a build flag that defaults to debug)?

## Static signals
Raw exception returned to the client:
- Node/Express: `res.status(500).json({ error: err })`, `res.json({ stack: err.stack })`, `res.send(err.stack)`
- Node: `process.on('uncaughtException', e => res.send(e))`, `process.on('unhandledRejection', ...)`
- Python/Django/Flask/FastAPI: `return jsonify({'error': str(e)})`, `raise e` in a handler with `DEBUG=True`, `app.run(debug=True)`, `traceback.format_exc()` written to response
- Java: `e.printStackTrace()`, `response.getWriter().print(e.getMessage())`, Spring `@ExceptionHandler` returning `ex.toString()` / `ex.getStackTrace()`
- Go: `http.Error(w, err.Error(), 500)` (leaks the raw driver/OS error text)
- PHP: `echo $e->getMessage()`, `echo mysqli_error($conn)`, `or die(mysql_error())`, `var_dump($e)`
- Ruby/Rails: `render plain: e.message`, `render json: { error: e.full_message }`

Debug pages enabled in production:
- Express: missing `NODE_ENV=production`; `app.use(expressWinston(...))` with `meta:true` in prod
- Django: `DEBUG = True` (and `ALLOWED_HOSTS` open), `django.views.debug`
- Laravel: `APP_DEBUG=true`, `APP_ENV=local`
- Spring Boot: `server.error.include-stacktrace=always`, `server.error.include-message=always`, `management.endpoints.web.exposure.include=*`
- ASP.NET: `<customErrors mode="Off"/>`, `ASPNETCORE_ENVIRONMENT=Development`
- PHP: `display_errors=On`, `error_reporting(E_ALL)` with Whoops `whoops->register()` in prod
- GraphQL/Apollo: `formatError` not overridden → `extensions.exception.stacktrace` returned

## False positives
- Production returns a generic message (`{ "error": "internal_error", "trace_id": "..." }`) and the full stack is only in server logs — protected. A correlation ID that is random (not the raw exception) is fine.
- Stack traces appear only in a developer-facing admin UI gated behind strong authentication and restricted to an internal network — lower risk, but still verify the gate.
- The error page shows a framework banner that is intentionally published (e.g. a static "Powered by" footer) and reveals no version or path detail.
- `display_errors` / debug page is enabled in a clearly non-production, ephemeral dev container with no real data — out of scope for a production audit.
- A 4xx error legitimately echoes the *validated* user input (echo of `?q=foo` as `foo`) without any server-side stack/path — that is a validation concern, not stack-trace exposure.

## Attack scenario
1. Attacker sends a malformed request designed to trigger an unhandled exception — e.g. an oversized payload, a malformed JSON body, or a path that hits an unguarded DB query: `POST /api/orders { "id": "abc' OR 1=1--" }`.
2. The application has no global error handler (or one that returns `err`), so the response body contains the full stack trace, the SQL fragment, and the absolute path `/var/www/api/src/orders.js:142`.
3. From the stack trace the attacker learns: the framework and version (Express 4.x + Sequelize), the Node version, internal module names and structure, and the DBMS driver in use.
4. The attacker cross-references the versions against a CVE database, finds a known deserialization flaw in that Sequelize/Node combination, and crafts a targeted follow-on exploit — collapsing days of blind reconnaissance into minutes.

## Impact
- **Confidentiality**: disclosure of internal architecture, file layout, library/framework versions, SQL schema hints, and sometimes secrets accidentally embedded in error messages or environment variables dumped by a debug page.
- **Integrity**: indirect — the leaked detail accelerates injection / RCE / path-traversal chains; the error itself does not modify data.
- **Availability**: indirect — version/structure disclosure makes DoS or exploit targeting far more reliable.
- Severity scales with what the trace reveals: a bare `internal_error` message is informational; a trace exposing a vulnerable dependency version, a DB connection string, or a debug page leaking `process.env` rises to High.

## Remediation
Never serialize the raw exception to the client; log the detail server-side and return a generic message with a correlation ID:
```ts
// VULNERABLE — raw error and stack trace returned to the client
app.use((err, req, res, next) => {
  res.status(500).json({ error: err, stack: err.stack, message: err.message });
});

// SAFE — generic message + correlation ID; full detail only in server logs
app.use((err, req, res, next) => {
  const traceId = req.headers['x-request-id'] || crypto.randomUUID();
  logger.error({ traceId, err, path: req.path }, 'unhandled error');
  res.status(500).json({ error: 'internal_error', trace_id: traceId });
});
```
Defense-in-depth: force `NODE_ENV=production` (Express hides stack traces by default), disable debug pages in every non-dev environment (`DEBUG=False`, `APP_DEBUG=false`, `server.error.include-stacktrace=never`, `customErrors mode="RemoteOnly"`/`On`, `display_errors=Off`), and override Apollo `formatError` to strip `extensions.exception`. Add an automated check that fails the build/deploy if any debug flag is set in production.

## References
- OWASP ASVS V7.4 / V14.4 — Error handling must not expose sensitive information; centralized, generic errors
- OWASP WSTG-ERRH-01 — Testing for Improper Error Handling
- OWASP Cheat Sheet: Error Handling, Logging
