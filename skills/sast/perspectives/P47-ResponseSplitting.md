---
id: P47
name: ResponseSplitting
area: V1 Encoding and Sanitization
refs: ASVS V5.3.x / WSTG-INPV-07 / CS: Injection Prevention
---

# P47 — Response Splitting (CRLF Injection)

## Overview
HTTP Response Splitting (also called CRLF injection) occurs when **request-controlled input containing carriage-return/line-feed characters (`\r\n`)** is written into a response **header value** without stripping control characters. By injecting a raw `\r\n`, an attacker can terminate the intended header, start a new header (e.g. a second `Set-Cookie` or a `Location`), inject a blank line that ends the header block, and then begin writing the response **body** — effectively "splitting" one HTTP response into two. Modern frameworks (Express, Django, Spring, .NET) reject or encode CR/LF in header values, so the bug is now most often found in raw header manipulation, legacy code, custom HTTP/SMTP servers, redirect handlers that build `Location` strings by concatenation, and cookie generation that interpolates user input. The root cause is always the same: untrusted data reaches a header-writing sink without validation against the HTTP token/field-content grammar. Even when full response splitting is blocked, bare CR/LF can still enable header injection, log injection, and mail header injection (a sibling issue on SMTP/IMAP paths).

## What to check
- Does any handler write request-derived data (`req.query`, `req.params`, `req.body`, `req.headers`, `req.path`, `req.cookies`) into a **response header** — `res.setHeader`, `res.append`, `Location`, `Set-Cookie`, `Content-Disposition`, custom `X-*` headers, redirect targets?
- Are redirect targets built by **string concatenation** with user input (`res.redirect('/next?return=' + req.query.returnUrl)`) and is the resulting `Location` value checked for `\r\n`?
- Is user input interpolated into a `Set-Cookie` value (`name`, `value`, `path`, `domain`, or attribute) where a CR/LF could inject a second cookie?
- Are CR (`\r`, `\x0d`) and LF (`\n`, `\x0a`), including the URL-encoded forms `%0d`/`%0a`, **stripped or rejected** before the value reaches the header sink? Note: rejecting only `\n` is insufficient — some parsers accept a lone `\r`.
- Does the framework/server actually enforce CRLF rejection at the header-write boundary, or does it silently accept or pass through raw bytes? (Old Node.js, raw `http` module, hand-rolled servers, and CGI-style code are most exposed.)
- Does the same input also flow to **log files**, **email headers** (`mail()`, `smtplib`), or **CSV export**? CRLF injection there causes log forging / mail header injection (a parallel finding).
- Are values written via `Content-Disposition: attachment; filename="..."` where a `\r\n` could inject headers?

## Static signals
Header writes fed by request data (sink patterns):
- Node/Express: `res.setHeader('X-...', req.headers['x-...'])`, `res.setHeader('Location', url)`, `res.redirect(req.query.next)`, `res.cookie('sess', req.body.x)`, raw `res.writeHead(200, { 'X-Trace': req.header('x-trace') })`
- Python: `self.send_header('Location', path)` (stdlib `http.server`), `response['Location'] = path` (Django `HttpResponse`), `set_cookie(..., value=user)` — stdlib `http.server` does **not** strip CRLF
- Java: `response.setHeader("Location", url)` (Servlet), `response.addHeader(...)`, `response.sendRedirect(url)` — Servlet ≤4 rejects; verify container version
- Go: `w.Header().Set("Location", r.URL.Query().Get("next"))` — `net/http` sanitizes since Go 1.7
- PHP: `header('Location: ' . $_GET['next'])`, `setcookie('x', $_GET['v'])` — `header()` rejects embedded newlines since PHP 5.1.2; older/custom code may not
- Ruby/Rails: `response.headers['X-Foo'] = params[:foo]`, `redirect_to params[:return_url]` — Rack rejects CR/LF in header values
- .NET: `Response.Headers.Add("Location", returnUrl)`, `Response.Redirect(url)` — `HttpListener`/Kestrel reject CRLF

String concatenation into redirect/cookie/location values (the common precursor bug):
- `res.redirect('/dashboard?next=' + req.query.next)`
- `"Location: {}\r\n".format(user_url)` / `f"Location: {user_url}"`
- `setcookie('lang', $_POST['lang'])` with no CRLF check

## False positives
- The framework rejects or encodes CR/LF at the write boundary and that protection is verified active for the deployed version (Express `res.setHeader` throws `ERR_INVALID_CHAR`; Django/Rack/Spring/Kestrel strip or reject; Go `net/http` ≥1.7; PHP `header()` ≥5.1.2). Confirm the version and that the code path reaches the protected sink, not a raw socket.
- The input was validated against a strict allow-list (URL host allow-list, integer ID, UUID, enum) before reaching the header — it cannot carry control characters.
- The value is a server-generated constant or trusted config, not request-derived.
- The sink is a **response body** (not a header) — there CR/LF is harmless from a splitting standpoint (re-classify; it may still be a log-injection or XSS concern, not P47).
- Input was URL-decoded and `%0d`/`%0a` would be present; if the code only checks the raw (still-encoded) string for `\r\n`, that is a real gap, not an FP — flag it.

## Attack scenario
1. A login handler builds a redirect: `res.redirect('/welcome?name=' + req.query.name)` and writes the result into the `Location` header without CRLF validation.
2. Attacker supplies `name=foo%0d%0aSet-Cookie:%20sessionid=attacker%0d%0a%0d%0a<script>...</script>`.
3. After URL-decoding, the `Location` value contains a raw `\r\n`, terminating the intended header and injecting a second `Set-Cookie` plus a blank line and attacker-controlled body content.
4. The browser/proxy parses two logical responses: the first leaks the injected cookie (or in older proxies enables cache poisoning where the second body is served to other users), and the injected body executes in the victim's origin (escalating to stored/reflected XSS via P38/P39).
5. Variants: inject a `Content-Length: 0` to truncate the real body, a `Set-Cookie` to fixate the session (session fixation), or poison an intermediary cache so the crafted body is served to subsequent victims.

## Impact
- **Confidentiality**: injected cookies/session fixation, cache poisoning that serves attacker-controlled content to other users, leakage of subsequent headers.
- **Integrity**: arbitrary body content under the application's origin (escalates to XSS — see P38/P39); forged `Set-Cookie`; log forging that obscures attacker activity.
- **Availability**: cache poisoning can replace legitimate content; log forging complicates incident response.
- Severity scales with the position of the sink (a `Location`/`Set-Cookie` allows both splitting and XSS; a custom `X-*` header may allow only header injection) and whether an intermediary cache is involved (cache poisoning turns a one-shot bug into a worm-like vector).

## Remediation
Never interpolate raw request data into a header; validate against a strict grammar (printable ASCII field-content, no CR/LF/NUL) and prefer framework redirect/cookie helpers that enforce it:
```ts
// VULNERABLE — user input written to a header value with no CRLF check
app.get('/trace', (req, res) => {
  res.setHeader('X-Trace', req.header('x-trace'));        // %0d%0a → header injection
});

// SAFE — reject control characters and validate the redirect target
app.get('/trace', (req, res) => {
  const v = req.header('x-trace') ?? '';
  if (/[\r\n\0]/.test(v)) return res.status(400).end();   // strip CR/LF/NUL
  res.setHeader('X-Trace', v);
});

app.get('/go', (req, res) => {
  const next = req.query.next;
  if (!/^\/[A-Za-z0-9._~\-/]*$/.test(next)) return res.status(400).end(); // relative, allow-listed charset
  res.redirect(next);
});
```
As defense-in-depth: (1) keep the framework up to date so its CRLF rejection stays active, (2) for redirect targets use an allow-list of permitted destination hosts, and (3) apply the same CR/LF/NUL stripping to any log, mail-header, or CSV sink that consumes the same input (log/mail header injection is the same root cause on a different channel).

## References
- OWASP ASVS V5.3.x — Output encoding and injection prevention (header/HTTP response splitting controls)
- OWASP WSTG-INPV-07 — Testing for HTTP Splitting/Smuggling
- OWASP Cheat Sheets: Injection Prevention, HTTP Response Splitting
