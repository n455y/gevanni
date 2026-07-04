---
id: P12
name: CredentialTransport
area: V6 Authentication
refs: ASVS V2.x / V9.x / WSTG-ATHN-01, WSTG-CRYP-03 / CS: Transport Layer Security, Authentication Cheat Sheet
---

# P12 — CredentialTransport

## Overview
Credential-transport weaknesses arise when passwords, API keys, bearer tokens, or other secrets traverse or persist in **channels that expose them**: plaintext HTTP, URL query strings, log files, exception traces, error messages, or cached intermediaries. Even when the application itself is hardened, a single `console.log(req.body)` or an `Authorization` header captured in an error report hands the credential to anyone with access to logs or monitoring. The root causes are predictable: sending secrets over cleartext, placing them in URL components that proxies and browsers record (history, `Referer`, access logs), and failing to scrub secrets from application and infrastructure logs. TLS protects the wire; it does nothing for the URL, the logs, or the redirect that drops the user back to HTTP.

## What to check
- Are credentials ever placed in the URL — query string (`?password=`, `?token=`, `?api_key=`), path component, or matrix parameter? URLs are logged by proxies, CDNs, load balancers, and browser history.
- Is the login / token endpoint served over plaintext HTTP, or does it accept HTTP and merely redirect to HTTPS (a redirect the attacker can intercept with sslstrip-style tooling when HSTS is absent)?
- Are full request bodies or headers logged unfiltered (`console.log(req.body)`, `app.use(morgan('combined'))` capturing the Authorization header, Django middleware logging `request.META`)?
- Does structured-logging / APM instrumentation auto-capture request headers or body (Sentry `beforeSend`, OpenTelemetry `http.request.headers`) without an allow-list scrubber?
- Are credentials echoed into error messages, stack traces, or validation messages returned to the client (`"Invalid password 'hunter2'"`, SQL error revealing the token)?
- Are secrets stored in source control, container env files, build artifacts, or front-end bundles shipped to the browser?
- Is HTTP Basic Auth used, and if so, over HTTPS only? Basic Auth base64 is trivially reversible and offers no protection on its own.
- Is HSTS enabled with `includeSubDomains` and a long `max-age` to prevent first-visit and downgrade attacks?
- Are session tokens / JWTs transmitted in cookies without the `Secure`, `HttpOnly`, and `SameSite` attributes?

## Static signals
Credentials in URL / query:
- `fetch(`http://api.example.com/login?user=${u}&password=${p}`)`
- `requests.get('http://.../login', params={'username': u, 'password': p})`
- Python: `urllib.request.urlopen(f'http://...?token={api_key}')`
- Java: `new URL("http://.../auth?api_key=" + key)`, `HttpURLConnection`
- Go: `http.Get("http://.../login?token=" + tok)`
- PHP: `header('Location: http://.../reset?token=' . $token)`
- Ruby: `Net::HTTP.get(URI("http://.../?key=#{key}"))`

Plaintext transport / no HSTS:
- `app.listen(80)`, no TLS config, `http://` scheme in upstream calls
- Node: no `https` server, missing `helmet.hsts()`
- Python Flask: `app.run(ssl_context=None)` / no reverse-proxy TLS guarantee
- Missing response header: `Strict-Transport-Security`
- HTTP Basic over `http://`: `Authorization: Basic` without TLS

Secret leakage into logs:
- `console.log(req.body)`, `console.log('login body', req.body)`
- `logger.info(f"auth header: {request.headers['Authorization']}")`
- Python: `logging.debug(request.body)`, `print(request.POST)`
- Java: `log.info("Headers: " + request.getHeaders())`
- Go: `log.Printf("req body: %s", body)`
- PHP: `error_log(print_r($_REQUEST, true))`
- Express middleware capturing headers: `app.use(morgan(':req[Authorization]'))`

APM/error auto-capture:
- Sentry / Bugsnag / Datadog `beforeSend` without redacting `Authorization`, `Cookie`, body
- OpenTelemetry instrumentations capturing `http.request.headers` / `http.response.headers`
- Spring Boot `server.tomcat.accesslog.pattern` including `%h %{Authorization}i`

Secrets in client bundles / VCS:
- Hardcoded keys in front-end: `const API_KEY = '...'`, `process.env` inlined via webpack DefinePlugin
- `.env` committed; Dockerfile `ENV SECRET=...` baked into image

## False positives
- HSTS with `includeSubDomains` + a TLS-terminating reverse proxy that forces HTTPS and rejects plaintext on the auth path — the wire is protected. Still confirm cookies carry `Secure`.
- Basic Auth over an enforced HTTPS-only channel with HSTS — acceptable risk for some internal/admin APIs, though token-based auth is preferred.
- Tokens that are by design short-lived, single-use, and bound to a transaction (e.g., a one-time password-reset token in a URL link) — URL leakage risk is mitigated by single-use semantics and short TTL; verify there is no `Referer` leakage to third-party assets and the token expires.
- Logging redaction is centralized (e.g., Express middleware that strips `password`/`Authorization` before any logger sees it) — confirm coverage of all sinks, including error handlers.
- The "credential" is a public identifier (tenant ID, client public key), not a secret.

## Attack scenario
1. Attacker sits on the same coffee-shop Wi-Fi as the victim (ARP spoofing / rogue AP) while the victim authenticates to an app that serves its login page over HTTP and only redirects to HTTPS — or sets no HSTS.
2. The initial POST carrying the password crosses the wire in cleartext; the attacker captures it with a packet sniffer.
3. Alternatively, the app logs `req.body` to stdout; an attacker with read access to the log aggregator (a leaked API key, an over-permissioned SIEM account, or a third-party paste from a prior breach) greps for `password` / `Authorization`.
4. A second vector: a reset link of the form `https://app/reset?token=...` leaks the token via the `Referer` header to a third-party analytics script on the success page, exposing it to whoever controls that script.
5. The attacker replays the captured credential or token against the live API and authenticates as the victim.

## Impact
- **Confidentiality**: total — captured passwords/tokens grant full account access; password reuse turns one leaked credential into many.
- **Integrity**: attacker acts as the victim — funds transfers, data modification, privilege abuse.
- **Availability**: account lockout, destructive changes, ransomware-style data deletion.
- Severity scales with privilege: an operator/admin credential leaked to logs can become full-tenant compromise. URL-based token leakage is often High even when wire TLS is enforced, because the sink (logs, `Referer`, history) is outside the app's control.

## Remediation
Send credentials only in request bodies over TLS, never in URLs; scrub every log sink:
```ts
// VULNERABLE — credential in URL + logged body
fetch(`http://api/login?user=${u}&password=${p}`);
console.log('login body', req.body);

// SAFE — POST body over HTTPS, secrets excluded from logs
fetch('https://api/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: u, password: p }),
});
// centralized redaction middleware strips password/Authorization before any logger
```
```python
# VULNERABLE
logging.info(f"auth header: {request.headers['Authorization']}")

# SAFE — allow-list what is logged
logging.info("login attempt user=%s", request.form.get('username'))
```
Defense-in-depth: enforce HTTPS with HSTS (`max-age>=63072000; includeSubDomains; preload`), set cookies with `Secure; HttpOnly; SameSite=Lax|Strict`, configure APM `beforeSend` to drop `Authorization`/`Cookie`/secret-bearing bodies, and treat any secret in a URL as already compromised.

## References
- OWASP ASVS V2.x (Authentication) and V9.x (Communications / TLS) — credential transport and protection in transit
- OWASP WSTG-ATHN-01 (Credentials Transported over an Encrypted Channel), WSTG-CRYP-03 (Sensitive Data Sent via Unencrypted Channels)
- OWASP Cheat Sheets: Transport Layer Security, Authentication, Password Storage
