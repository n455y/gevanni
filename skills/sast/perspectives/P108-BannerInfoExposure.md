---
id: P108
name: BannerInfoExposure
refs: ASVS V14.3.x / WSTG-CONF-07, WSTG-INFO-02 / CS: Error Handling
requires: [backend]
---

# P108 — BannerInfoExposure

## Overview
Banner information exposure occurs when an application or its infrastructure discloses identifying technical details — server software, framework, language runtime, library versions, OS, or internal hostnames — through HTTP response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`) or through default/verbose error pages (stack traces, "Whitelabel Error Page", Django debug page, Tomcat version block). The root cause is shipping with default disclosure settings enabled: web servers and frameworks advertise themselves by default, and unhandled exceptions fall through to a developer-oriented page that prints the stack. Banner exposure is an information-discovery primitive, not a direct exploit — it shrinks the attacker's reconnaissance cost, letting them fingerprint the exact patch level and immediately target known CVEs for that version instead of probing blindly.

## What to check
- Does any response include a `Server` header carrying product and version (e.g. `nginx/1.25.3`, `Apache/2.4.58`, `Microsoft-IIS/10.0`)?
- Is `X-Powered-By` present with framework/runtime detail (`Express`, `PHP/8.2.1`, `ASP.NET`, `Servlet/3.1`)?
- Are framework/version fingerprint headers emitted (`X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `X-Runtime`, `X-Version`, `Via`, `X-Drupal-Cache`, `X-Pingback`)?
- Do unhandled errors return a default page showing the stack trace, framework name/version, file paths, environment values, or SQL (e.g. Django debug, Spring Whitelabel, Tomcat 500 page, Express default error handler, Laravel `APP_DEBUG=true`, Next.js error overlay)?
- Are custom 404/500 handlers actually registered, or does the framework fall back to its default (informational) page?
- Does the application set a restrictive `Server` token or expose internal hostnames/IPs in headers or error bodies?
- Are CORS or debug endpoints (`/actuator`, `/__debug__`, `/trace`) reachable that leak build/version metadata?

## Static signals
Banner/version headers left at defaults:
- Node/Express: `const app = express();` with no `app.disable('x-powered-by')`; missing `helmet()`
- Go: `http.ListenAndServe(addr, mux)` — default writes `Server`/`Date`; `Server{}` without a custom handler still leaks
- Python Flask: `app.run()` without `server_header` override; default 500 page in debug shows the Werkzeug debugger
- Python Django: `DEBUG = True` renders the technical 500 page with settings/SQL/stack
- PHP: default `expose_php = On` adds `X-Powered-By: PHP/x.y.z`; `display_errors = On` prints versioned fatal errors
- Java Spring Boot: no `server.error.include-stacktrace=never` / `include-exception=false`; default Whitelabel page leaks "Spring" + version on certain configs
- Java/Tomcat: `server.xml` `<Connector server="Apache-Coyote/1.1">` default `Server` header
- ASP.NET: `<httpRuntime>` with no `<httpProtocol><customHeaders>` removal of `X-Powered-By`/`X-AspNet-Version`
- Ruby/Rails: `config.middleware.delete(Rack::Runtime)` missing; default `X-Runtime` and `Server` headers
- Nginx: `server_tokens on;` (default) → `Server: nginx/1.x.x` and 404 footer version
- Apache: `ServerTokens Full` (default) and `ServerSignature On` → footer version on error pages

Default/missing error handlers:
- Express: no `app.use((err, req, res, next) => ...)` → HTML stack trace in dev
- FastAPI: no custom exception handler → JSON with type/module paths
- Spring: `@ControllerAdvice` absent → Whitelabel Error Page
- Django: `DEBUG=True` → full traceback page (never ship this)

## False positives
- The banner is intentionally generic and version-stripped (`Server: nginx`, `Server: web`) AND errors are handled by a sanitized custom page — this is the desired state, low/no severity.
- Version hiding is "security through obscurity": banner suppression alone does not fix an unpatched server. Do not over-rate findings whose only issue is a stripped header; pair with patch-level verification.
- Headers originate from an edge proxy/CDN the application does not control (Cloudflare, AWS ALB) — report against infrastructure config, not application code.
- The version shown is already public and EOL/patched; the residual risk is the unpatched software, not the disclosure.

## Attack scenario
1. Attacker sends `curl -I https://app.example.com/` and reads `Server: Apache/2.4.49` and `X-Powered-By: PHP/7.4.21`.
2. Attacker cross-references those versions against an exploit database; Apache 2.4.49 is vulnerable to CVE-2021-41773 (path traversal / RCE), PHP 7.4.21 has known issues.
3. Attacker sends the path-traversal request and reads `/etc/passwd` or uploads a webshell, achieving remote code execution — directly enabled by the version disclosure that made reconnaissance a single HTTP request.

## Impact
- **Confidentiality**: precise tech-stack and patch-level disclosure accelerates targeted exploitation; stack traces leak file paths, internal structure, secrets, and config values.
- **Integrity**: version fingerprinting enables immediate targeting of version-specific RCE/auth-bypass CVEs.
- **Availability**: known version-specific DoS CVEs become trivially applicable.
- Severity scales with the gap between the disclosed version and current patch level: an outdated, exposed version that maps to a critical RCE is high risk; a current, exposed version is informational/low.

## Remediation
Suppress version banners and replace default error pages with generic ones:
```ts
// VULNERABLE — default Express banner + default error page
import express from 'express';
const app = express();
app.get('/search', (req, res) => { throw new Error('boom'); });
app.listen(3000);

// SAFE — banner removed, helmet hardening, sanitized error handler
import express from 'express';
import helmet from 'helmet';
const app = express();
app.disable('x-powered-by');
app.use(helmet());               // drops X-Powered-By, sets security headers
app.use((err, _req, res, _next) => {
  // log full error server-side, return generic message client-side
  req.log.error({ err }, 'request failed');
  res.status(500).type('text').send('Internal Server Error');
});
app.listen(3000);
```
Pair header/banner suppression with infrastructure hardening (Nginx `server_tokens off;`, Apache `ServerTokens Prod` + `ServerSignature Off`, PHP `expose_php = Off` + `display_errors = Off`, Django `DEBUG = False`, Spring `server.error.include-stacktrace=never`). Treat banner hiding as defense-in-depth — the primary control is keeping all components patched to current versions.

## References
- OWASP ASVS V14.3.x — Unintended information disclosure (banners, version strings)
- OWASP WSTG-CONF-07 — Test HTTP Strict Transport Security, banners & headers
- OWASP WSTG-INFO-02 — Fingerprint web server / application framework
- OWASP Cheat Sheet: Error Handling (avoid leaking stack traces and version info)
