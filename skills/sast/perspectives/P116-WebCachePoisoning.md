---
id: P116
name: WebCachePoisoning
area: V13 Configuration
refs: ASVS V14.x / WSTG-CONF / CS: Web Cache Poisoning
---

# P116 — Web Cache Poisoning

## Overview
Web cache poisoning occurs when an attacker-controlled, **unkeyed** request input — typically an HTTP header such as `Host`, `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, or `X-Forwarded-For` — is reflected into a response that a shared cache (CDN, reverse proxy, gateway) then stores and serves to every subsequent visitor for that cache key. The cache key is normally derived from the path and a curated subset of headers; any request property that influences the response body but is excluded from the key is an "unkeyed" input and a potential poisoning vector. The root cause is a mismatch between the inputs the **origin** trusts to build the response and the inputs the **cache** uses to differentiate entries. The result is a single malicious request that "infects" a cached resource (often a static JS bundle, CSS, or a public page) so that all other users receive the attacker's payload until the TTL expires or the entry is purged.

## What to check
- Does any handler echo request headers into the response **body** or generated **URLs** without those headers being part of the cache key? Trace `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`, `Forwarded`, `Referer`, and any custom `X-*` header from the raw request to the rendered output.
- Is absolute URL generation (canonical links, Open Graph tags, `<base href>`, redirects, JSON-LD, OAuth callback/issuer, password-reset links, SAML/entityID) derived from `Host`/`X-Forwarded-*` rather than a server-side configured base URL?
- Does a redirect (`30x Location`) reflect an unkeyed header value, and is that redirect cached (`Cache-Control: public/max-age` or cache-defaults-on)?
- Are unkeyed headers used to select an origin (path/request routing, virtual-host selection, A/B bucket, locale, tenant) that changes the cached body?
- **Fat GET**: does the handler honor a request **body**, `Content-Length`, or `Transfer-Encoding` on a `GET` (or read `GET` body) such that the body influences a cached response while the cache key only covers path+query?
- **Cache-key injection / parameter cloaking**: is the cache key built from raw query string such that `?utm=1;param=poison` or duplicated/encoded parameters (`?a=1&a=2`, `%3f`, `%23`) collapse or hide parameters the origin reads but the cache does not key on?
- Are error/debug pages, sitemaps, health, or "not found" responses that reflect the host/URL cacheable (`Cache-Control` missing or `public`)?
- Does served JavaScript derive DOM values (third-party import URLs, analytics endpoint, dynamic `import()`, `<script src>` built from `document.location`/`location.host`/`document.referrer`) from a value that an unkeyed header can manipulate — i.e. **DOM-based cache poisoning** of a cached JS file?
- Does the CDN/cache normalize keys differently from the origin (case-folding, trailing slash, header reordering, semicolon params, path normalization) creating an unkeyed oracle?
- Are `Vary`/`Cache-Control`/`Surrogate-Control` headers set incorrectly (missing `Vary` on a variant, or `Vary: *` ignored by the cache tier)?
- Are purge/invalidation endpoints unauthenticated, allowing an attacker to force re-population with a poisoned entry?

## Static signals
Origin trusting forwarded headers without allow-listing the proxy:
- Node/Express: `req.headers['x-forwarded-host']`, `req.get('host')` used to build a URL; `app.set('trust proxy', true)` (or `all`) combined with `req.protocol`/`req.hostname`; `res.redirect(req.headers['x-forwarded-proto'] + '://...')`
- Python: `request.host`, `request.host_url`, `url_for(_external=True)`, `request.headers.get('X-Forwarded-Host')`, `request.access_route[0]` (Flask/Django `SECURE_PROXY_SSL_HEADER`, `USE_X_FORWARDED_HOST=True`)
- Java/Spring: `request.getServerName()`, `ServletUriComponentsBuilder.fromCurrentRequest()`, `request.getHeader("X-Forwarded-Host")`; `server.forward-headers-strategy=NATIVE` without a trusted-proxy allow-list
- Go: `r.Host`, `r.Header.Get("X-Forwarded-Host")`, `httputil.ReverseProxy` director that copies `X-Forwarded-*`
- PHP: `$_SERVER['HTTP_HOST']`, `$_SERVER['HTTP_X_FORWARDED_HOST']`, `$_SERVER['SERVER_NAME']` populated from Host
- Ruby/Rails: `request.host`, `request.original_url`, `config.action_controller.trusted_proxies`, `X-Forwarded-Host` reflected in mailer URLs
- Cloudflare/CDN: `Cache-Control: public, max-age=3600` on a host-derived response; cache rules that drop `Vary` or strip headers before keying; Workers reading `request.headers.get('host')` into the response

Fat GET / body on GET:
- Handlers that call `req.body`/`request.json()`/`@RequestBody` on `GET`/`HEAD`; `Transfer-Encoding: chunked` parsed on GET; body read for idempotent verbs.

Cache-key / routing misconfig:
- `Cache-Control: public` on redirects, 404s, or host-derived pages; missing `Vary` on responses that branch on a header; `Vary: User-Agent` with UA normalization differences between edge and origin.
- CDN config (Cloudflare Cache Rules, Fastly VCL, AWS CloudFront cache policy) with an **allow-listed-header** cache policy that omits a header the origin reads.

DOM-based poisoning in cached JS:
- `import('https://' + location.host.split('.')[0] + '.cdn/x.js')`, `fetch('/' + new URLSearchParams(location.search).get('api'))`, `<script src="${location.origin}/bundle.js">` inside a cached static file built from request-derived host.

## False positives
- The header is **behind a trusted proxy** that unconditionally overwrites it (`X-Forwarded-Host` set by the edge, not accepted from clients) and the origin rejects/sanitizes client-supplied values — confirm the overwrite happens before any reflection and that direct-to-origin access is blocked.
- The response is **not cacheable**: `Cache-Control: private, no-store` (or `Authorization` present, which most shared caches refuse to store), and no upstream CDN caches it.
- The reflected value is **part of the cache key** (e.g. the edge keys on `Host` and `Host` is the only reflected input) so a poisoned entry only re-poisons the attacker's own key.
- The reflected value is validated against an allow-list (known internal domains) before use.
- The page is single-tenant/fully static with no request-derived bytes in the body.

## Attack scenario
1. Attacker probes `https://app.example.com/` and observes the response includes `<link rel="canonical" href="https://app.example.com/">` where the host is taken from the `X-Forwarded-Host` header, and the page is cached (`Cache-Control: public, max-age=600`, no `Vary` on that header).
2. Attacker sends one request with `X-Forwarded-Host: evil.attacker.com` (or `X-Original-URL`, or a fat GET body, or a cloaked param). The origin renders `<link rel="canonical" href="https://evil.attacker.com/">` and returns it.
3. The cache stores this response **under the benign key** `GET /` because `X-Forwarded-Host` is unkeyed.
4. For the next 600 seconds every legitimate visitor to `https://app.example.com/` receives the poisoned canonical — which, combined with an import-map, Open Graph, JSONP/import, or a redirect, loads attacker-controlled content/JS.
5. If the cached resource is a JS bundle, the attacker achieves persistent XSS for all users until TTL/purge, without any victim interaction beyond loading the page.

## Impact
- **Integrity**: served content is attacker-controlled — persistent XSS, credential harvesting, session hijack, defacement affecting all users behind the cache node. Worse than reflected XSS because one request compromises many victims with no per-victim interaction.
- **Confidentiality**: exfiltration of session data, auth tokens, PII rendered by the poisoned page.
- **Availability**: redirect loops, broken assets, or forced routing to an attacker origin can deny service; mass poisoning can take a region offline.
- Severity scales with **TTL**, **cache share** (single edge vs global CDN), and **sensitivity** of the poisoned resource (a cached API response or admin static asset is critical; a transient 404 is low).

## Remediation
Strip unkeyed headers at the trust boundary and derive URLs from configuration, not from the request:
```ts
// VULNERABLE — Host-derived canonical URL on a cached page
app.get('/', (req, res) => {
  res.set('Cache-Control', 'public, max-age=600');
  res.render('home', { canonical: `${req.protocol}://${req.get('host')}/` });
});

// SAFE — fixed base URL from config; ignore client-supplied forwarded host
const BASE_URL = process.env.PUBLIC_BASE_URL; // https://app.example.com
app.set('trust proxy', 1);                 // trust one hop only
app.get('/', (req, res) => {
  res.set('Cache-Control', 'public, max-age=600');
  res.vary('X-Forwarded-Host');             // or, better, don't read it at all
  res.render('home', { canonical: `${BASE_URL}/` });
});
```
Defense-in-depth: configure the CDN cache key to include **every** header the origin reads; set explicit `Vary` for variant responses; make redirects and error pages `Cache-Control: private, no-store`; reject bodies/`Transfer-Encoding` on idempotent verbs; authenticate purge endpoints; and treat all `X-Forwarded-*`/`X-Original-*`/`Forwarded` headers as client-controlled unless a trusted proxy overwrites them first.

## References
- OWASP ASVS V14.x — Configuration and HTTP security (architectural / proxy hardening)
- OWASP WSTG-CONF — Configuration and deployment management testing; cache behavior
- OWASP Cheat Sheet: Web Cache Poisoning (unkeyed headers, cache-key injection, fat GET, DOM-based poisoning)
