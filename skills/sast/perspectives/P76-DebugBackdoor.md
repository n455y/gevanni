---
id: P76
name: DebugBackdoor
area: V15 Secure Coding and Architecture
refs: ASVS V10.x, V14.3 / WSTG-CONF-05, WSTG-ATHN-05 / CS: Third Party JavaScript, Session Management
---

# P76 — DebugBackdoor

## Overview
A debug/test/admin backdoor is any endpoint, route, or authentication branch left in production that allows unauthenticated or under-authenticated privileged access — arbitrary code execution (`/exec`, `/eval`), hidden admin panels (`/__dev`, `/__inspect`), bypass flags (`?debug=1`, `?backdoor=...`), or always-on debug toolbars. The root cause is leftover scaffolding from development that was never gated behind an environment check, removed before release, or protected with weak/credentialed auth. Unlike a logic bug, these are intentional conveniences that ship to prod and grant an attacker a direct path to RCE, data exfiltration, or auth bypass with a single unauthenticated request.

## What to check
- Are there routes/endpoints for code execution, file manipulation, shell access, or heap/inspect that exist in production builds (`/exec`, `/eval`, `/run`, `/shell`, `/__inspect`, `/__dev`, `/actuator`, `/admin/debug`)?
- Is any route registered **unconditionally** rather than guarded by `NODE_ENV !== 'production'`, `APP_ENV`, a feature flag, or compile-time stripping?
- Are there query-param or header bypass flags that skip authentication, return verbose errors, or expose internal state (`?debug=`, `?admin=`, `?test=`, `X-Debug`, `?backdoor=`)?
- Is there a hardcoded "magic" credential, token, or API key that grants admin regardless of the normal auth flow (a "skeleton key")?
- Are debug/inspection middleware enabled globally and reachable — Express `logger`/`morgan` dev format, Spring Boot Actuator env/heapdump endpoints, Django `runserver` exposed, PHP `xdebug`, Ruby `web-console`/`better_errors`, Node `--inspect` bound to `0.0.0.0`, Next.js dev overlays?
- Does the build pipeline (Webpack/Next.js/SvelteKit/Nuxt) include dev-only tools, source maps, or REPL endpoints in the production artifact?
- Are admin/ops tools protected only by obscurity (no auth) or weak auth (basic auth, shared password, IP allowlist that can be spoofed)?

## Static signals
Unconditional debug/exec routes:
- Node/Express: `app.get('/__exec'`, `app.use('/__inspect'`, `app.get('/eval'`, `res.send(eval(req.query` / `eval(req.body`, `vm.runInThisContext(req.query`
- Python: `app.route('/exec')`, `eval(request.args`, `exec(request.form`, `subprocess.check_output(request.args['cmd'], shell=True)`, `__import__('os').system(`
- Java/Spring: `@GetMapping("/actuator/**")` with env/heapdump exposed without auth; `Runtime.getRuntime().exec(req.getParameter`
- Go: `http.HandleFunc("/debug/pprof"`, `os/exec.Command(r.URL.Query().Get("cmd"))`, `net/http/pprof` imported in main
- PHP: `eval($_GET['c'])`, `system($_GET['cmd'])`, `shell_exec`, `preg_replace('/.*/e'`
- Ruby: `get '/console'`, `eval(params[:c])`, `binding.pry`/`better_errors` in production gemfile

Bypass / verbose flags:
- `if (req.query.debug === '1')`, `if (req.headers['x-debug']`
- `?admin=true`, `?test=1`, `?skip_auth=`, `?backdoor=`, `?internal=`
- `if (user.id === 'root') // bypass`, hardcoded `if (password === 'letmein')`
- Spring `management.endpoints.web.exposure.include: '*'`, `debug=true` in `application.properties`

Dev tooling left on:
- Node: `app.listen(port, '0.0.0.0')` alongside `--inspect`; `express-dump`, `morgan('dev')` in prod
- Rails: `web-console`, `better_errors` not constrained to `group :development`
- Django: `DEBUG=True` shipped; `runserver 0.0.0.0:8000` in a prod entrypoint
- Next.js/Nuxt: dev server (`next dev`, `nuxt dev`) as the prod process; React error-boundary overlays exposed
- Source maps served (`devtool: 'eval'`, `sourcemap: true`) leaking original source

## False positives
- Route is gated by both a production-environment check **and** strong auth (RBAC/role check, MFA), and the build explicitly strips dev routes in prod. Confirm both conditions hold, not just one.
- The endpoint is an internal-only health check (`GET /health`, `/ready`) returning a constant string with no sensitive data and no code execution — typically Low/Informational.
- An ops/admin tool is network-segmented (private subnet, mTLS, IP allowlist enforced at the load balancer/firewall with anti-spoofing) — still note weak auth as defense-in-depth risk.
- `eval`/`exec` operates on a server-generated, allow-listed constant, not on request data — confirm no request value flows into the executed string.
- Debug logging writes to server-side files only, never echoes to the response.

## Attack scenario
1. Attacker enumerates the target and finds `/actuator/env` (Spring) or `/__inspect` (Node) responding `200` without auth.
2. Using Spring `env` → `heapdump`, the attacker downloads the JVM heap and extracts database credentials / JWT signing keys / cloud secrets from memory.
3. Or: attacker hits `/__exec?c=require('child_process').execSync('env').toString()` and gets direct RCE, reading `DATABASE_URL` and `AWS_SECRET_ACCESS_KEY`.
4. Or: attacker appends `?debug=1` to a login endpoint that returns a verbose stack trace exposing internal paths and a hardcoded backdoor token; uses it to bypass auth.
5. With RCE or stolen secrets the attacker pivots to the DB, exfiltrates user data, plants persistence, or moves laterally to internal services.

## Impact
- **Confidentiality**: full source/secret/DB exposure via inspect endpoints or heap dumps; credential theft enables lateral movement.
- **Integrity**: arbitrary code execution allows data tampering, account creation, backdoor implantation.
- **Availability**: RCE lets the attacker wipe data, ransomware-encrypt, or DoS the host and dependent services.
- Severity scales from **High** (verbose debug info / auth bypass on a non-admin endpoint) to **Critical** (unauthenticated RCE or admin-console disclosure of secrets). An internet-reachable `/eval` or heap-dump endpoint is almost always Critical.

## Remediation
Gate every debug/exec route behind an environment check **and** strong auth; strip them from production builds entirely:
```ts
// VULNERABLE — always-on code execution route, no auth, no env guard
app.get('/__exec', (req, res) => res.send(eval(req.query.c)));

// SAFE — only in non-production, behind RBAC, request never reaches eval
if (process.env.NODE_ENV !== 'production') {
  app.get('/__dev/exec', requireRole('developer'), requireMfa, (req, res) => {
    // allow-listed operations only; never eval raw request input
    res.json({ ok: true });
  });
}
```
Defense-in-depth: never `eval`/`exec` request-controlled input in any environment; remove dev-only middleware from the prod bundle; disable or firewall-gate Spring Actuator (`management.endpoints.web.exposure.include: health` + `management.endpoint.env.enabled: false`); ensure `DEBUG=False` and no `web-console` in prod; serve source maps only to authenticated staff or not at all.

## References
- OWASP ASVS V10.x — Malicious code / unauthorized functionality; V14.3 — unauthorized access to admin/ops interfaces
- OWASP WSTG-CONF-05 — Review old, backup, and unreferenced files for administrative/debug interfaces; WSTG-ATHN-05 — testing for bypassing authentication schemas
- OWASP Cheat Sheets: Third Party JavaScript, Session Management; Spring Boot Actuator security hardening guidance
