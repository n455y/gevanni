---
id: P60
name: SensitiveDataLogging
area: V16 Security Logging and Error Handling
refs: ASVS V7.1.x, V8.3.x / WSTG-INFO-02 / CS: Logging
---

# P60 — SensitiveDataLogging

## Overview
Sensitive-data logging occurs when secrets or regulated data — passwords, API keys, bearer tokens, session cookies, PII, payment card numbers, government IDs, biometric data — are written to application logs, error reports, audit trails, or crash dumps **in plaintext or with insufficient masking**. Unlike a direct exfiltration attack, this is a self-inflicted disclosure: the application itself persists the secret to infrastructure that is often broadly readable (log aggregators, SIEM, object storage, APM traces) and retained far longer than the original transaction. The root cause is almost always dumping a whole request object (`req.body`, `req.headers`, an exception with `.config`/`.request` attached) instead of an allow-listed subset, or a logger that serializes full objects by default. Because log systems rarely encrypt at rest with the same rigor as the primary datastore, a single log line can become a compliance breach (PCI DSS, GDPR) and a credential-leak vector.

## What to check
- Does any log/audit/debug statement write request-derived objects whole — `req.body`, `req.headers`, `ctx.request`, `request.POST`, `Request.*` — without an explicit allow-list or deny-list of sensitive fields?
- Are authentication secrets ever logged directly: passwords, PINs, OTPs, refresh tokens, API keys, bearer tokens, `Authorization` headers, session cookies, `Set-Cookie` values?
- On error/exception paths, does the logged object carry secrets transitively? Watch `axios`/`requests`/`OkHttp` errors whose `.config`/`.request`/`response.config` includes `headers.Authorization`; ORM errors that echo bind parameters; stack traces dumped with environment variables.
- Are regulated data classes logged unmasked: full PAN (card number), CVV/CVC (must never be stored/logged at all), SSN/national ID (My Number, Aadhaar, CNP), dates of birth, biometric templates, health (PHI) fields?
- Is PII masking correct and reversible-safe? `password` replaced with literal `"********"` is fine; truncating the middle of a card (`4111******1111`) is PCI-permissible but verify the masking regex does not leak the full value in adjacent log fields.
- Do framework defaults defeat masking? `JSON.stringify(req.body)` before masking, `repr(e)` that prints the full request, `util.inspect` with high depth, `structlog` rendering the full event dict.
- Are secrets written to secondary sinks reachable from logs: distributed-tracing spans (`span.setTag('authorization', ...)`), APM error breadcrumbs, metric tags/labels, debug query logs (`knex.debug`, Django `LOGGING db.backends` with params), SSRF target URLs that embed tokens?
- Does `DEBUG`/`TRACE` level logging in production widen exposure — verbose serializers (Pino `serializers: { req }`, Spring `LoggingInteceptor`, Rails `log_level = :debug`) that dump full headers/bodies?

## Static signals
Whole-object / unfiltered logging (the most common pattern):
- Node: `console.log(req.body)`, `console.log(req.headers)`, `logger.info(req.body)`, `logger.info(req.headers)`
- Node (Pino/Express): `logger.info({ req }, 'request')` with `serializers.req` returning full headers
- Node (Koa): `ctx.logger.info(ctx.request)` / `ctx.body`
- Python: `logging.info(request.body)`, `logger.info(request.POST)`, `logger.info(request.META)`, `print(f"headers={request.headers}")`
- Python (Django): `LOGGING['db.backends']` with `django.db.backends` capturing params
- Java: `log.info("headers={}", request.getHeaderNames())`, `log.error("failed", e)` where `e` prints `request.headers`
- Java/Spring: `LoggingInterceptor` / `CommonsRequestLoggingFilter` with `setIncludePayload(true)` + `setIncludeHeaders(true)`
- Go: `log.Printf("req=%+v", r)`, `log.Println(r.Header)`, Zap/Slog `Sugared.Infof("body=%s", body)`
- PHP: `error_log(print_r($request->headers, true))`, `Log::info($request->all())` (Laravel), `file_put_contents('debug.log', var_export($_POST, true))`
- Ruby/Rails: `Rails.logger.info(request.headers)`, `logger.debug(params)`, full params logging in production (`config.log_level = :debug`)

Secrets logged directly:
- `logger.info('login', { user, password })` / `logger.info('token=' + token)` / `console.log('auth', req.headers.authorization)`
- Python: `logger.info("password=%s", password)`, `log.debug(f"api_key={API_KEY}")`
- Java: `log.info("Authorization: {}", request.getHeader("Authorization"))`
- Go: `log.Printf("cookie=%s", r.Header.Get("Cookie"))`

Error objects leaking secrets (very high false-negative rate in manual review):
- Node (axios): `catch (e) { logger.error(e) }` — `e.config.headers.Authorization`, `e.request`, `e.response.config`
- Node (fetch): logging `Response` / `Request` objects with `headers` set
- Python (requests): `except Exception as e: log.error(repr(e))` — `e.request.headers`
- Python: `log.exception(...)` printing `__dict__` of custom exceptions that store the request
- Java: `log.error("call failed", ex)` where the exception message embeds the request URL/headers

Trace/APM/tag sinks:
- `span.setTag('authorization', token)`, `tracer.setUserData(...)`, OpenTelemetry `attributes` including `http.request.header.authorization`
- Datadog/Sentry `tags` or `extra` set to `req.headers`; Sentry `beforeSend` not scrubbing
- Metrics: `counter.labels(req.headers.authorization)` (cardinality + leak)

Masking present but insufficient:
- `logger.info(req.body)` after masking only top-level `password`, missing nested `user.credentials.secret`
- regex mask `s/\b\d{16}\b/****/g` misses cards with spaces/dashes, or leaves CVV field untouched
- `JSON.stringify` applied before the mask runs

## False positives
- A logging wrapper sanitizes via an explicit deny-list/allow-list (`redact()`, Pino `redact: ['req.headers.authorization', 'req.body.password', '*.password']`) and the path checked is covered by it — confirm nested globs match the actual key path.
- Only an opaque, server-generated identifier is logged (hashed user id, pseudonymous correlation id, token id without the token) — this is the recommended pattern.
- The logged value is a non-secret by construction (a UUID request id, an enum status, a public key/certificate fingerprint, an error code) and cannot be reversed to a credential.
- Card/PAN logging is intentionally truncated to PCI-permissible `BIN + last4` (`4111******1111`) and CVV/CVC is never logged.
- The application runs in an isolated dev/test scope with synthetic data and the logger is gated behind a non-production env check (`if (process.env.NODE_ENV !== 'production')`) — still flag for hardening, but lower severity.
- A central log shipper performs field-level redaction before persistence (verify the rule actually fires and covers all secret-bearing fields, not just top-level).

## Attack scenario
1. The application has `logger.info('login attempt', req.body)` on the auth route and ships logs to a centralized ELK/Splunk/Datadog cluster with broad read access (all engineers + support).
2. An attacker with read access to the log store (compromised developer laptop, over-permissioned service account, leaked CI/CD credentials, or a chained SSRF that can reach the logging API) queries logs for `password` or `authorization`.
3. Within minutes they harvest live plaintext passwords and bearer tokens from recent login attempts.
4. They reuse captured bearer tokens directly against the API (no brute force needed) or pivot using the plaintext passwords against other services where users reused them.
5. Alternatively, a subpoena/breach of the log archive — retained for years, rarely encrypted at rest with envelope keys tied to KMS — exposes every user's credentials for the full retention window, a far larger blast radius than the primary auth store which only stored password hashes.

## Impact
- **Confidentiality**: direct disclosure of credentials (passwords, tokens, API keys) enabling account takeover and lateral movement; mass PII/PHI/card exposure; loss of session confidentiality.
- **Integrity**: stolen admin credentials allow data tampering, fraudulent transactions, privilege changes.
- **Availability**: leaked operational secrets (DB/cloud credentials) can enable destructive attacks (ransomware, infrastructure deletion).
- Severity scales with retention breadth: a secret that lived one request in memory is a minor issue; the same secret persisted to a 1-year, multi-tenant, internet-adjacent log archive is a critical compliance and security incident (PCI DSS 3.x violation for PAN/CVV, GDPR Article 32 breach for PII at scale).

## Remediation
Log only allow-listed, non-secret fields; never dump request objects whole:
```ts
// VULNERABLE — whole request body logged, includes password/otp/token
app.post('/login', (req, res) => {
  logger.info('login attempt', req.body);
  // ...
});

// SAFE — explicit allow-list; secrets never reach the logger
app.post('/login', (req, res) => {
  logger.info('login attempt', {
    username: req.body.username,
    ip: req.ip,
    requestId: req.id,
  });
  // ...
});
```
For defense-in-depth, add a centralized redaction layer (Pino `redact` paths, a custom `format`/`transport`, or an interceptor on the logger) that scrubs known secret keys (`password`, `token`, `authorization`, `secret`, `*.cvv`, `pan`) at the sink — this catches secrets even when an individual call site forgets to allow-list. Ensure error objects are serialized with a sanitizer that drops `request`/`config`/`headers` before logging (`pino.stdSerializers.err` style), and set production log level to `INFO` or above to avoid `DEBUG`/`TRACE` payload dumps.

## References
- OWASP ASVS V7.1.x — Log all access and events; do not log sensitive data
- OWASP ASVS V8.3.x — Protect sensitive data, including from logging
- OWASP WSTG-INFO-02 — Fingerprinting / information gathering via logs and error messages
- OWASP Cheat Sheet: Logging — what to log, what never to log, redaction
- PCI DSS 3.x req. 3 & 10 — never store/log full PAN or CVV; restrict and protect audit logs
