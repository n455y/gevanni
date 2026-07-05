---
id: P126
name: ServiceWorkerSecurity
refs: ASVS V3.x / WSTG-CLNT / CS: Service Worker, HTML5
requires: [frontend]
---

# P126 — ServiceWorkerSecurity

## Overview
A Service Worker (SW) is a script the browser registers against an origin and runs in the background, able to intercept **all** network requests in its scope via a `fetch` event handler. Because a SW persists across page loads, runs outside the page lifecycle, and sits transparently between the page and the network, any compromise becomes long-lived: a poisoned SW can rewrite or cache responses indefinitely, observe authenticated traffic passing through its handler, and survive a normal page refresh. The root risks are (1) lax scope so a SW registered under a user-controllable or shared path can hijack sibling paths, (2) serving the SW script itself over insecure transport or from a path the attacker can write to, (3) caching of authenticated/sensitive responses that then leak to other users or to disk, and (4) unvalidated `postMessage` channels that let any same-origin (or spoofable) context drive privileged logic inside the worker.

## What to check
- **Scope and registration path**: Is `navigator.serviceWorker.register(scriptUrl, { scope })` called with a `scope` broader than the script's own directory, or is the script served from a path that does not enforce the "script-directory prefix" rule (e.g. via `Service-Worker-Allowed`)? A SW can only control paths at or below its script's directory unless the server raises the limit.
- **Script integrity / transport**: Is the SW script (`sw.js` / `service-worker.js`) served over plain HTTP (mixed content on an HTTPS site), or fetched from a third-party/CDN origin without SRI (`integrity`) or version pinning? A MITM or compromised host can inject a persistent malicious SW.
- **`Service-Worker-Allowed` abuse**: Does the server send `Service-Worker-Allowed: /` to let a SW registered from `/blog/sw.js` (or any user-content path) take over the whole origin?
- **Fetch-handler interception of authenticated responses**: In the `fetch` event handler, are responses from authenticated endpoints (`Authorization`, session cookie) inspected, logged, or stored — or are `navigate`/`cors` requests for sensitive routes routed through `caches.match()`?
- **Caching sensitive data**: Does `caches.open(...).put()` store responses containing PII, tokens, account numbers, or per-user data into a long-lived Cache? Cache entries survive logout and may be read by the next user of a shared device or by any same-origin script.
- **Stale-cache integrity bypass**: After a code/patch release, does the SW serve an old (vulnerable) cached version of the app to users, delaying the rollout of a security fix indefinitely?
- **`postMessage` to/from the SW**: Does `event.source.postMessage(...)` or `self.addEventListener('message', ...)` act on `event.data` without checking `event.origin` and the caller's identity? Can any opener/iframe drive SW logic (push subscription, cache deletion, token refresh) cross-context?
- **`clients.claim()` / `skipWaiting()`**: Does the SW call `clients.claim()` and `skipWaiting()` unconditionally so a new (or attacker-injected) SW takes control of already-open tabs immediately, bypassing the safe reload window?
- **Push / background sync**: Are push subscription endpoints (`PushManager.subscribe`) created with `userVisibleOnly:false` (silent push) or VAPID keys shipped to the client, enabling silent tracking or key abuse?
- **Unregistration / cleanup**: Is there a documented unregistration path, or can a malicious SW remain installed after the legitimate app stops referencing it (orphaned SW)?

## Static signals
Registration and scope:
- `navigator.serviceWorker.register(`  with a `scope` option, especially `scope: '/'` or `scope: '../'`
- `Service-Worker-Allowed` header set to `/` or a parent path in server config (nginx `add_header Service-Worker-Allowed /;`, Express `res.set('Service-Worker-Allowed','/')`)
- `register('//cdn.example.com/sw.js')` or `register('http://...sw.js')` (cross-origin / insecure)

Fetch handler and caching:
- `self.addEventListener('fetch', (event) => { ... event.respondWith(caches.match(event.request)) })`
- `event.respondWith(caches.match(event.request))` returned **before** checking `event.request.mode === 'navigate'` or the request URL
- `cache.put(request, response)` / `cache.addAll([...])` against authenticated API paths (`/api/users`, `/account`, `/me`)
- `caches.match()` with `{ ignoreSearch: true }` or `{ ignoreMethod: true }` collapsing distinct authenticated requests onto one cached response
- `new Response(...)` synthesised inside the fetch handler from request-derived data (HTML rewrite, XSS sink)

Message handling:
- `self.addEventListener('message', (event) => { ... })` with no `event.origin` / `event.source` check before acting on `event.data`
- `event.source.postMessage(token, '*')` — replying with a token/secret to any origin (`'*'` target)
- Page-side `swRegistration.active.postMessage(secretData)` sending secrets to a SW whose script source is not pinned

Control takeover:
- `self.skipWaiting()` and `clients.claim()` called unconditionally at top level of the SW
- `clients.claim()` without a version/signature guard

Transport / integrity:
- `sw.js` served by a route mounted on plain HTTP (e.g. Vite/Webpack dev middleware, Express static over `http://`)
- Missing `integrity` on `<link rel="serviceworker">` / `register(url, { integrity })` (browsers ignore SRI for SW today — so cross-origin SW URLs are an elevated risk)

## False positives
- The SW scope is correctly limited to its own directory (script at `/app/sw.js`, scope `/app/`) and no `Service-Worker-Allowed` escalation header is set — the browser's default scope restriction is intact.
- The SW caches only public, static, non-personal assets (app shell, fonts, images) and never caches responses to `Authorization`-bearing or cookie-authenticated requests; a `cacheKey` excludes credentials.
- The fetch handler uses a *stale-while-revalidate* or *network-first* strategy with an explicit allow-list of cacheable URL prefixes and passes everything else through (`return fetch(event.request)`) — authenticated traffic is never read or stored.
- `event.origin` (or `event.source.url`) is checked against an allow-list in the `message` handler before any privileged action, and replies use the specific `event.source` client, not `'*'`.
- The site is served fully over HTTPS, the SW script is same-origin under a path the attacker cannot write to, and registration is gated behind a version check.

## Attack scenario
1. The application lets users host content under `/~user/` and serves `Service-Worker-Allowed: /` on every path (misconfigured static server).
2. Attacker uploads `/~attacker/sw.js` and registers it client-side with `scope: '/'`; the browser allows it because of the elevated header.
3. The SW installs a `fetch` handler that, for any authenticated `navigate` request, returns a cached page with an injected credential-stealing script, and that `caches.put()`s responses from `/api/account` for later exfiltration.
4. Any victim who has visited the attacker's page now has the SW controlling **all** paths on the origin across future sessions — refreshing, closing, and reopening the tab does not remove it.
5. The SW persists because `skipWaiting()` + `clients.claim()` take over open tabs immediately and there is no unregister path; even after the legit app is patched, victims keep loading the compromised cached version.

## Impact
- **Confidentiality**: SW sees every request/response in scope, including authenticated API calls, tokens in headers/bodies, and personal data — full session-content disclosure; cached copies leak to subsequent device users.
- **Integrity**: attacker-controlled responses let the SW rewrite any page, inject scripts, or fabricate API responses — persistent XSS / data tampering that survives logout and refresh.
- **Availability**: a malicious or buggy SW can return offline/cached error pages, block all network access for the origin, or hold users on a vulnerable app version forever.
- Severity scales with scope and persistence: a whole-origin SW (`Service-Worker-Allowed: /`) on an authenticated app is near-total account compromise; a SW scoped to `/static/` caching only images is low. Persistence (survives refresh, often survives logout) is what makes SW compromise materially worse than a one-shot reflected flaw.

## Remediation
Pin the SW to its own directory, never cache authenticated responses, and validate every message channel:
```js
// VULNERABLE — over-broad scope, caches auth responses, open postMessage
navigator.serviceWorker.register('/sw.js', { scope: '/' });

// sw.js
self.addEventListener('fetch', (event) => {
  event.respondWith(caches.match(event.request));        // caches /api/account too
});
self.addEventListener('message', (e) => {
  refreshToken(e.data);                                  // no origin check
});
self.skipWaiting(); clients.claim();                     // instant takeover
```
```js
// SAFE — minimal scope, allow-listed cache, guarded message
navigator.serviceWorker.register('/app/sw.js');          // default scope = /app/

// sw.js
const CACHEABLE = /^\/(static|img|fonts)\//;             // public assets only
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || !CACHEABLE.test(url.pathname)) {
    return;                                              // auth/API bypasses cache
  }
  event.respondWith(caches.match(event.request).then(r => r || fetch(event.request)));
});
self.addEventListener('message', (event) => {
  if (event.origin !== self.origin) return;              // same-origin only
  // act on event.data ...
});
```
Defense-in-depth: serve the SW script only over HTTPS from a non-writable path, never set `Service-Worker-Allowed` to a parent of user content, version the cache so security rollouts invalidate stale entries, and add a CSP that restricts `script-src`/`connect-src` to limit what even a hijacked SW can load.

## References
- OWASP ASVS V3.x — Web frontend / session and transport controls
- OWASP WSTG-CLNT — Testing for client-side security (Service Workers, storage)
- OWASP Cheat Sheet: HTML5 Web Security, Service Worker security guidance
