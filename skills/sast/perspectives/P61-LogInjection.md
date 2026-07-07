---
id: P61
name: LogInjection
refs: ASVS V7.1.x / WSTG-INPV-12 / CS: Logging
---

# P61 — LogInjection

## Preconditions

The code writes logs.


## Overview
Log injection occurs when request-controlled input — username, URL path, header value, search term, error reason — is written into a log line **without sanitizing newlines and control characters**. Because most log sinks (files, syslog, stdout parsed by containers) are line-oriented, an attacker who can embed `\n`, `\r\n`, or ANSI escape sequences can forge fake log entries, overwrite or hide legitimate records, poison SIEM correlation rules, and confuse incident response. The root cause is plain-text string concatenation of untrusted data into a log message; using structured (JSON) logging or escaping newlines and control bytes before emission neutralizes the threat. A secondary risk is log forging via terminal escapes (`\x1b[2J`) that clear screens or fake "INFO" prefixes in operations dashboards.

## What to check
- Does any handler concatenate request-derived data (`req.body`, `req.query`, `req.params`, `req.headers`, `req.path`) into a free-text log message via template literal, `+`, `%s`, or `format()`?
- Are newline characters (`\n`, `\r`, `\r\n`), NUL bytes, and ANSI/terminal escape sequences (`\x1b[...`) stripped or escaped before the value reaches the sink?
- Does the application log plain text into files/syslog/stdout that downstream tools (grep, `tail`, ELK, Splunk, CloudWatch) parse line-by-line? If so, CRLF injection is exploitable.
- Are values that an attacker fully controls — `User-Agent`, `Referer`, `X-Forwarded-For`, username on failed login, path/query in 404 logs — interpolated verbatim?
- Is structured logging (JSON Lines, Bunyan, Pino, Logstash JSON, Logback `JSONLayout`) used consistently, or only for some loggers while others still call `console.log` / `print` / `logger.info("msg " + x)`?
- Does the logging framework auto-escape newlines (Winston, Logback `replace`) — and was that behavior left enabled?
- Could forged logs evade detection: impersonate a higher-severity level, fake an audit "login ok" for a user who never authenticated, or inject a fake stack trace?
- Are logs ingested by a SIEM with pattern-matching rules an attacker could misdirect by forging lines that match (or fail to match) a detection?

## Static signals
String concatenation / interpolation into free-text log messages:
- Node: `log(\`login ok: ${req.body.user}\`)`, `log.info('UA=' + req.headers['user-agent'])`, `console.log('path', req.path)`
- Python: `logger.info(f'user {name} logged in')`, `logging.info('search=%s' % q)`, `log.info('UA: ' + ua)`
- Java: `log.info("login: " + username)`, `logger.error("bad path " + request.getRequestURI())`
- Go: `log.Printf("user %s done", r.URL.Path)`, `fmt.Fprintln(w, "x="+v)`
- PHP: `error_log("auth fail: " . $user)`, Laravel `Log::info("user {$name}")`
- Ruby: `Rails.logger.info("search #{params[:q]}")`, `logger.debug("UA " + ua)`
- C# / .NET: `_log.LogInformation("login {User}", username)` (structured, safe) vs `_log.LogInformation("login " + username)` (concatenated, unsafe)

Structured logging done right (safe — value carries metadata, framework escapes):
- Node Pino: `log.info({ event: 'login', user })`
- Python structlog / json-logging: `log.info('login', user=name)`
- Java Logback JSON / Jackson encoder: `MDC.put("user", name)`
- .NET Serilog: `Log.Information("login {@Event}", new { user })`

Suspicious patterns near logs:
- Raw `req.headers['x-forwarded-for']`, `user-agent`, `referer` placed in a log message without sanitization.
- Custom `sanitize()`/`truncate()` wrappers around log calls that exist *but are bypassed* in error paths (`catch (e) { log.error(e.message + ' ' + userInput) }`).

## False positives
- The logging framework is structured (JSON Lines) and the framework itself escapes newlines/control chars inside string fields — confirm the value is passed as a field, not concatenated into the message template.
- The input is validated against a strict allow-list (UUID, integer, enum, base64 token) that cannot contain `\n` or escapes.
- The value originates from a server-generated source, not the request (e.g. an internal correlation ID).
- The logger explicitly strips `\r`/`\n`/`\x00`/`\x1b` via a layout encoder (Logback `<replace>`, Winston custom format, a wrapping `clean()` helper applied to every user value).
- The sink is a binary/append-only audit store that records length-prefixed or protobuf records rather than line-delimited text.

## Attack scenario
1. Attacker attempts login with username `admin\n[INFO] login ok: admin from trusted-console`.
2. The server logs `login failed: admin\n[INFO] login ok: admin from trusted-console` to a plain-text file.
3. The two physical lines in the file look like a genuine failure followed by a genuine trusted-console success — an auditor or SIEM rule reading line-by-line sees a valid admin login.
4. Alternatively the attacker injects `\r` to overwrite the visible line in a terminal/tail window, or ANSI `\x1b[2J\x1b[H` to clear the operator's screen, hiding the real failed-login attempt.
5. During incident response, the forged entries misdirect analysts to the wrong actor, wrong time, or wrong "trusted" source.

## Impact
- **Confidentiality**: low direct data exposure, but forged/hid logs blind monitoring and can mask real breaches.
- **Integrity**: log records can be fabricated, overwritten, or deleted-from-view — undermining audit trails, compliance evidence (PCI DSS, SOC 2), and non-repudiation.
- **Availability**: SIEM alerts can be flooded (forged lines trigger or suppress detections); terminal escapes can render operator consoles unusable.
- Severity scales with how logs are consumed: a SIEM that auto-correlates or an audit trail relied on for billing/legal action amplifies impact far beyond a dev-only log file.

## Remediation
Use structured logging and pass untrusted data as fields, never concatenated into the message:
```ts
// VULNERABLE — plain concatenation, CRLF/ANSI injectable
app.post('/login', (req, res) => {
  log.info(`login ok: ${req.body.user}`);   // attacker controls newlines
});

// SAFE — structured logging; framework escapes control chars in fields
app.post('/login', (req, res) => {
  log.info({ event: 'login', status: 'ok', user: String(req.body.user) });
});
```
If free-text logging is unavoidable, sanitize every user value through a helper that strips `\r`, `\n`, `\x00`, and `\x1b` (or replaces them with a visible token) and cap its length. Defense in depth: enforce structured JSON output at the logger/layout level and treat plain-text concatenation as a lint/CI failure.

## References
- OWASP ASVS V7.1.x — Log injection protection / logging best practices
- OWASP WSTG-INPV-12 — Testing for Log Injection (log forging)
- OWASP Cheat Sheet: Logging
