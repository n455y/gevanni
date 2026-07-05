---
id: P72
name: HSTS
refs: ASVS V9.1.1, V14.4.2 / WSTG-CONF-07 / CS: HTTP Strict Transport Security
requires: []
---

# P72 — HSTS

## Overview
HTTP Strict Transport Security (HSTS) instructs compliant browsers to access the site **only over HTTPS** for a defined period, neutralizing SSL-stripping / man-in-the-middle downgrade attacks. Without it, a user who types `example.com` (or clicks an `http://` link, or connects to a hostile network that injects a redirect) can be silently bridged to plaintext HTTP, where credentials, cookies, and session tokens are exposed. The issue is purely a **missing or weak response header** — `Strict-Transport-Security` absent, set with too short a `max-age`, applied over HTTP (where it can itself be stripped), or scoped too narrowly (no `includeSubDomains`/`preload`) to cover the domain's attack surface. Root cause: TLS is correctly configured but the host never commits the browser to it.

## What to check
- Is `Strict-Transport-Security` set on **every** HTTPS response (200, 3xx, 4xx, 5xx), not just the login page or homepage?
- Is `max-age` at least `63072000` (≈2 years)? Shorter values (e.g. `31536000`/1yr, or a value that never gets refreshed) weaken the guarantee; `0` actively clears HSTS and is a red flag.
- Is the header ever sent over plain `http://`? HSTS must not be trusted from a cleartext response — an attacker on the wire can strip or forge it.
- Are the `includeSubDomains` and `preload` directives considered? Omitting `includeSubDomains` leaves any `http://sub.example.com` host exposed to SSL stripping; `preload` is required to close the first-visit gap (the HSTS list is baked into the browser).
- Does the app override or unset the header (reverse-proxy/LB config stripping it, framework disabling it, conditional logic that drops it for some routes)?
- Is the redirect from HTTP to HTTPS itself a `301`/`308` to the HTTPS URL, or a weak `302`/JS/meta refresh that is itself strippable before HSTS is established?
- Are mixed-content subresources (`http://` assets on an HTTPS page) present? These bypass HSTS protection for those requests.

## Static signals
Header set explicitly (Node/Express — Helmet):
- `app.use(helmet())` — Helmet sets HSTS **only in production** (`NODE_ENV=production`); in dev the header is omitted by default.
- `helmet.hsts({ maxAge: ..., includeSubDomains: ..., preload: ... })`
- Manual: `res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload')`

Weak / missing configuration patterns:
- `helmet.hsts({ maxAge: 0 })`, `maxAge: 3600`, `maxAge: '1 day'` — too short or resets HSTS
- `helmet.hsts({ includeSubDomains: false, preload: false })` — narrowed scope
- No `helmet()` or `helmet.hsts()` anywhere, and no manual `Strict-Transport-Security` setHeader
- Python/Django: missing or `SECURE_HSTS_SECONDS` low / `0`; `SECURE_HSTS_INCLUDE_SUBDOMAINS` not set; `SECURE_HSTS_PRELOAD` missing; `SECURE_SSL_REDIRECT = False`
- Python/Flask: `Talisman` absent, or `talisman = Talisman(app, strict_transport_security_max_age=...)` with a small/missing value
- Java/Spring: no `addHeader("Strict-Transport-Security", ...)`; `WebSecurityConfig` with no `.headers().httpStrictTransportSecurity(...)`; server (Tomcat) `relaxedQueryChars`/`securityHttpHeaders` config omitting HSTS
- Go: `w.Header().Set("Strict-Transport-Security", ...)` absent or short `max-age`; reverse-proxy stripping it
- PHP: no `header('Strict-Transport-Security: ...')`; Laravel `TrustProxies`/middleware without HSTS
- Ruby/Rails: `config.force_ssl = false`, or no `config.ssl_options = { hsts: { expires: ..., subdomains: ..., preload: ... } }`
- Nginx: `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"` missing inside the `server` (443) block, or added in the `http` block where it can be skipped by `add_header` in nested blocks (Nginx resets headers at the `server`/`location` level).
- Conditional/buggy logic: `if (req.secure) res.setHeader(...)` that misses terminated-TLS at a proxy where `req.secure` is always false; `app.use` ordering that places HSTS after error handlers.

## False positives
- Helmet is mounted and `NODE_ENV=production` is set — HSTS is applied automatically even without an explicit `helmet.hsts()` call.
- The header is set at the **edge** (CDN/WAF/load balancer) rather than in app code — confirm in the actual response (curl over HTTPS), not just source.
- The app is HTTP-only and intentionally not deployed over TLS (rare, internal-only) — HSTS is inapplicable, but flag the missing TLS separately.
- `includeSubDomains` is deliberately omitted because the domain hosts HTTP-only subdomains (e.g. legacy `intranet.`) — confirm with the owner; if so, downgrade to Medium but still note the residual exposure.
- First-visit window remains regardless of HSTS; this is inherent, not a defect — `preload` is the mitigation, not a hard requirement for every site.

## Attack scenario
1. Victim connects to a hostile network (rogue Wi-Fi, ARP-spoofed LAN, malicious ISP) and requests `http://app.example.com` (typed without scheme, or via an old link).
2. The attacker intercepts the cleartext request and answers it themselves over HTTP, serving the login page from `app.example.com` (SSL stripping) instead of letting the browser upgrade to HTTPS — HSTS is absent, so the browser never forces the upgrade.
3. The victim submits credentials; the attacker captures them or transparently proxies the session as a man-in-the-middle.
4. Because no HSTS pin exists, the browser shows no warning — the attack is invisible. With `preload` absent, even a first-time visitor on a clean network is exposed on that first hop.

## Impact
- **Confidentiality**: full credential/session interception — cookies, bearer tokens, posted form data, viewed content.
- **Integrity**: MITM can modify responses (inject scripts, swap download links, alter transactions) for the duration of the victim's connection.
- **Availability**: downgrade or content tampering can block or redirect users to malicious hosts.
- Severity scales with session value: a stripped session on a banking/admin app is critical; on a static marketing site, low. Persistency of the MITM depends on the network — any single hostile network can compromise a victim for the life of the stolen session.

## Remediation
Set HSTS at the edge or via framework middleware, on every HTTPS response, with a strong policy:
```ts
// VULNERABLE — no HSTS; browser can be downgraded to plaintext HTTP
app.get('/', (req, res) => res.send('hi'));

// SAFE — Helmet applies HSTS in production, all routes, all status codes
app.use(
  helmet.hsts({
    maxAge: 63072000,           // ~2 years
    includeSubDomains: true,    // cover every subdomain
    preload: true,              // eligible for the browser HSTS preload list
  })
);
```
Verify the header reaches the client: `curl -sI https://app.example.com | grep -i strict-transport-security`. Ensure the HTTP-to-HTTPS redirect is a strippable-then-pinned pattern (301/308) and that the preload list submission requirements (HTTPS on apex, `includeSubDomains`, `max-age>=31536000`) are met before submitting to `hstspreload.org`. Defense-in-depth: also enable `X-Content-Type-Options`, a restrictive CSP, and TLS that rejects downgrade via server-side config — HSTS protects the browser, but server-side TLS enforcement protects non-browser clients.

## References
- OWASP ASVS V9.1.1 (communications over TLS), V14.4.2 (HTTP security headers / HSTS)
- OWASP WSTG-CONF-07 — Test HTTP Strict Transport Security
- OWASP Cheat Sheet: HTTP Strict Transport Security
