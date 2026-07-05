---
id: P103
name: DebugMode
area: V13 Configuration
refs: ASVS V14.x / WSTG-CONF-02, WSTG-CONF-05 / CS: Error Handling
requires: [backend]
---

# P103 — DebugMode

## Overview
Leaving debug/diagnostic mode enabled in production is a configuration defect that exposes internals an attacker should never see — full stack traces with file paths and library versions, source maps that reconstruct the original source, interactive consoles (Django/Flask Werkzeug debugger, Laravel Ignition, PHP `display_errors`, ASP.NET developer exception pages), and verbose environment dumps that frequently leak secrets (`DATABASE_URL`, API keys, signing keys). The root cause is almost always an environment mismatch: the application keyes debug behavior off an unset or default flag (`NODE_ENV`, `APP_DEBUG`, `APP_ENV`), or a framework's pretty error page is shipped unguarded to production. The impact compounds — a single stack trace can reveal the framework, version, file layout, and SQL dialect, accelerating every other attack class on this list.

## What to check
- Is `NODE_ENV` (Node) unset or set to `development` in production? Express, Koa, Next.js, and most middleware alter behavior (stack traces in errors, `x-powered-by`, dev overlays) based on this value.
- Are framework debug toggles `True`/`on` in a production config: Django `DEBUG=True`, Flask `app.run(debug=True)` or `FLASK_DEBUG=1`, Laravel `APP_DEBUG=true`, Symfony `APP_ENV=dev`/`APP_DEBUG=1`, Rails `config.consider_all_requests_local=true`, Spring `server.error.include-stacktrace=always`?
- Does PHP expose `display_errors=On` / `error_reporting=E_ALL` in production php.ini?
- Are source maps (`.js.map`, `.css.map`) deployed to a web-accessible directory or served without authentication? Bundlers default to writing them next to the asset.
- Is an interactive debugger or REPL exposed on a reachable port (Werkzeug `/console`, Laravel Ignition, ASP.NET developer exception page, Vue/React devtools overlay)?
- Do error responses include stack traces, SQL fragments, internal hostnames, request bodies, or environment variables? Send a malformed request, invalid JSON, or trigger an unhandled exception.
- Are secrets rendered into error pages or logs via `process.env` dumps, `var_dump($_ENV)`, Spring `/env` or `/actuator/env`, Django technical 500 with `META`?
- Do verbose logging levels (`DEBUG`, `TRACE`, `sqlalchemy.echo=true`, Hibernate `show_sql`) ship to production and write secrets/tokens to logs?
- Are framework-level diagnostics routes exposed unauthenticated: Spring Boot Actuator (`/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/threaddump`), Rails `/rails/info/routes`, Django `DEBUG` static-file serving?

## Static signals
Debug-flag misconfiguration:
- Node/Express: `app = express()` with no `NODE_ENV` check; `app.get('env') === 'development'` gating prod code; missing `app.set('env','production')`
- `process.env.NODE_ENV !== 'production'` or unset → stack returned to client
- Django: `DEBUG = True` (settings.py); `DEBUG = os.getenv('DEBUG', 'True')` (default-on anti-pattern)
- Flask: `app.run(debug=True)`, `app.debug = True`, `FLASK_DEBUG=1`
- Laravel: `APP_DEBUG=true`, `APP_ENV=local` (`.env`); config cached with debug on
- Symfony: `APP_DEBUG=1`, `APP_ENV=dev` in `.env` shipped to prod
- Rails: `config.consider_all_requests_local = true`, `config.action_controller.consider_all_requests_local = true`
- Spring Boot: `server.error.include-stacktrace=always`, `server.error.include-binding-errors=always`, `management.endpoints.web.exposure.include=*` (actuator)
- PHP: `ini_set('display_errors', '1')`, `error_reporting(E_ALL)` in prod entrypoint; `display_errors = On` in php.ini
- ASP.NET: `ASPNETCORE_ENVIRONMENT=Development`, `app.UseDeveloperExceptionPage()` called unconditionally

Source maps / assets exposed:
- `devtool: 'source-map'`, `'eval-source-map'` (webpack) with no deployment guard
- `sourcemap: true` (Vite/Rollup) writing `.map` to the public output dir
- `.js.map` / `.css.map` present in `public/`, `dist/`, `static/`, `assets/`

Interactive debuggers reachable:
- Werkzeug `run_simple(..., use_debugger=True, use_reloader=True)` on `0.0.0.0`
- Laravel Ignition (pre-8.x default-on error page with runnable solutions)
- `var_dump`, `print_r`, `dd()`, `dump()`, `console.log(req)` left in handlers
- Spring Boot DevTools on classpath in prod build

## False positives
- Production sets `NODE_ENV=production` (or equivalent), debug toggles are off, and error responses are generic JSON/HTML ("Something went wrong, reference #abc"). Verify the actual prod config, not just the default branch.
- Source maps are generated but served only behind authentication or from a non-public path (e.g. uploaded to a private Sentry release, or `/.map` returns 404 on the public host).
- `app.UseDeveloperExceptionPage()` / `display_errors` is correctly gated by an `isDevelopment`/`isLocal` check that excludes production.
- Verbose logging is enabled but the log sink is access-controlled and does not capture secrets (no `Authorization` headers, no token values).
- Actuator endpoints are present but restricted (`management.endpoints.web.exposure.include=health,info` + Spring Security) and `env`/`heapdump` are disabled or authenticated.

## Attack scenario
1. Attacker sends a malformed request to a production endpoint: invalid JSON body, oversized header, or a query that triggers an unhandled exception (e.g. `/api/users?id='`).
2. The framework, in debug mode, returns a full technical error page: stack trace showing `app/controllers/UserController.js:42`, the ORM version, the SQL fragment, the database driver, and a `process.env` dump including `JWT_SECRET` and `DATABASE_URL=postgres://prod:pass@db.internal:5432/app`.
3. If an interactive debugger is enabled (Werkzeug, Laravel Ignition pre-fix, ASP.NET dev page), the attacker reads further or, in the Werkzeug case, reaches the `/console` endpoint and executes arbitrary Python via a PIN that can be derived from leaked machine details.
4. With the leaked secret the attacker forges JWTs or connects to the database directly, escalating from information disclosure to full compromise.

## Impact
- **Confidentiality**: source code, internal architecture, dependency versions, environment variables, secrets, and database structure are disclosed. Source maps effectively hand over the client-side source.
- **Integrity**: interactive debuggers (Werkzeug console, Ignition RCE pre-2021) allow remote code execution; leaked signing keys enable forged tokens and data tampering.
- **Availability**: exposed `/actuator/shutdown`, reloaders, or console access can be used to stop or crash the service.
- Severity scales steeply: a stack-trace leak alone is typically Medium, but the same misconfiguration frequently exposes secrets or an interactive console, raising it to High/Critical.

## Remediation
Force production-safe defaults and gate every debug path on the environment:
```ts
// VULNERABLE — debug-on by default, stack trace returned to client
const app = express();                       // NODE_ENV unset → "development"
app.get('/api/users', (req, res) => {
  throw new Error('DB connection failed');   // full stack trace sent to user
});

// SAFE — explicit prod mode, generic errors, headers hardened
if (process.env.NODE_ENV !== 'production') {
  app.use(require('morgan')('dev'));
  app.use(require('errorhandler')());        // dev-only pretty errors
}
app.use(require('helmet')());
app.disable('x-powered-by');
app.use((err, req, res, _next) => {
  // never leak internals in production
  res.status(500).json({ error: 'internal_error', ref: req.id });
});
```
Mirror this in every framework: Django `DEBUG=False` + `ALLOWED_HOSTS` set; Flask `debug=False` (or a production WSGI server like gunicorn with debug off); Laravel `APP_DEBUG=false` + `APP_ENV=production` + `php artisan config:cache`; Spring `server.error.include-stacktrace=never` and restrict Actuator; PHP `display_errors=Off` + `log_errors=On`. Deploy source maps to a private location (Sentry release artifacts, authenticated CDN) — never to the public web root. As defense-in-depth, run an automated config check in CI that fails the build if any production artifact enables a debug flag.

## References
- OWASP ASVS V14.x — Build & Deploy / Configuration — verify debug and admin interfaces are disabled in production
- OWASP WSTG-CONF-02 — Test Application Platform Configuration; WSTG-CONF-05 — Review Old Backup and Unreferenced Files for Sensitive Information
- OWASP Cheat Sheet: Error Handling (and relevant framework hardening guides)
