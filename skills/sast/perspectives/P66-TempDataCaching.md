---
id: P66
name: TempDataCaching
refs: ASVS V8.1.x, V8.2.x / WSTG-CRYP-01, WSTG-ATHN-06 / CS: Sensitive Data, Caching, Session Management
requires: [backend]
---

# P66 — TempDataCaching

## Overview
Sensitive responses — authenticated pages, API payloads returning PII, generated PDFs or reports, session/temp files — must be explicitly marked as non-cacheable. When a developer omits cache directives (or sets `Cache-Control: public`), browsers, forward/reverse proxies, and CDNs are free to store the response. The next user of the shared machine, an intermediary cache operator, or anyone probing a CDN edge can then replay cached authenticated content. The root cause is three-fold: (1) reliance on cache *defaults* instead of explicit `no-store`; (2) writing temp files (exports, backups, debug dumps) with world-readable permissions or predictable paths; and (3) serving sensitive content through caching layers not scoped to the authenticated principal. Each leaks confidentiality without any direct vulnerability in the application logic.

## What to check
- Does every authenticated/personalized endpoint emit an explicit `Cache-Control` header? The presence of a session cookie does **not** prevent caching; only `no-store` / `private, no-cache` does.
- Is any sensitive response served with `Cache-Control: public`, `max-age` > 0, or an `Expires` header in the future while the body contains PII, financial data, or auth state?
- Are CDN/reverse-proxy cache keys (Vary, surrogate keys) configured per-user, or is one user's response served to another from a shared key?
- Are generated artifacts (PDF reports, CSV exports, invoices) written to web-accessible or world-readable temp paths? Check `/tmp`, OS temp dirs, `public/`, `static/`, `uploads/`.
- Do temp files use predictable names (`report_<userid>.pdf`, sequential IDs) enabling enumeration by other tenants?
- Does the app clean up temp files after download, or do they persist until the OS reaps them?
- Are auth tokens, API keys, or credentials written to log files, browser local/sessionStorage, or intermediate caches in plaintext?
- Does the response include `Pragma: no-cache` / `Cache-Control: no-store` on logout/login flows so credentials and post-login pages are never cached?

## Static signals
Missing/disabled cache headers on sensitive responses:
- Node/Express: `app.get('/profile', (req,res) => res.json(user))` — no `Cache-Control`
- Node: setting the wrong policy `res.set('Cache-Control', 'public, max-age=3600')` on an authenticated route
- Spring (Java): `@Cacheable` on a controller method returning user-specific data; `response.setHeader("Cache-Control","public")`
- Django: `@cache_page(3600)` decorating a view that renders `request.user` data
- Flask: `@app.route('/account'); return render_template(...)` with no `after_request` setting no-store
- Rails: `expires_in 1.hour, public: true` in a controller serving current_user records

Caching layer / CDN misconfig:
- Varnish/Nginx: `proxy_cache` enabled but cache key omits the session cookie or Authorization header
- Nginx `proxy_cache_key "$scheme$request_method$host$request_uri";` (cookie/auth absent → cross-user cache poisoning)
- Cloudflare/Fastly page rules caching HTML behind a login

Temp-file / filesystem leaks:
- Node: `fs.writeFileSync('/tmp/report_'+userId+'.pdf', buf)` then served statically; `fs.writeFileSync('/app/public/export.csv', ...)`
- Python: `open(f'/tmp/{user_id}.json','w')`, `tempfile.NamedTemporaryFile(delete=False)` left readable
- Java: `new File(System.getProperty("java.io.tmpdir") + "/" + id + ".pdf")` with default 0644 perms
- Go: `os.WriteFile(filepath.Join(os.TempDir(), user+".txt"), b, 0644)`
- Ruby: `File.open("/tmp/#{user.id}.pdf", "w")`, `Tempfile.new` not unlinked

Credentials/PII persisted client-side:
- `localStorage.setItem('token', jwt)` / `sessionStorage.setItem('ssn', ...)`
- Writing the raw password / API key to a log: `console.log("login", password)`, `logger.info("auth", apiKey)`

## False positives
- The endpoint serves genuinely public, non-personalized content (marketing pages, public docs) — caching is correct and desirable. Verify the body really contains no per-user data.
- An explicit `Cache-Control: no-store, no-cache, must-revalidate` (or `private`) header is set on the response for every authenticated path, confirmed via runtime inspection, not just source guessing — framework defaults may already cover it (e.g., ASP.NET `[ResponseCache(NoStore = true)]`, Django `cache_control(no_store=True)`).
- Temp files are written to an OS private temp dir, created with restrictive mode (`0600`/`0700`), and unlinked immediately after the response stream completes; not web-accessible.
- The CDN caches only static assets (JS/CSS/images), never HTML or API JSON; cache keys are scoped per session.
- Storage of a non-sensitive display token (CSRF token tied to an authenticated session) — verify it is not a reusable credential.

## Attack scenario
1. Victim logs into the banking app on a shared library PC and views their account statement at `/account/statement`.
2. The endpoint returns a personalized JSON payload but emits no `Cache-Control` header, so the browser caches it to disk.
3. The attacker sits down at the same machine, opens the browser cache/offline storage (or uses a forensic tool), and reads the victim's statement — including balances and transactions — without any credentials.
4. Variant (CDN): the app sits behind a reverse proxy whose cache key omits the session cookie. User A requests `/api/profile`; the proxy stores the response keyed only by URL. User B requests the same URL and receives User A's profile from cache.
5. Variant (temp file): `/export?id=42` writes `/tmp/export_42.csv` (mode 0644) and serves it statically; another tenant on the host (or an LFI) reads `/tmp/export_42.csv` directly.

## Impact
- **Confidentiality**: disclosure of PII, financial records, medical data, or auth state to other users, cache operators, or forensic access on shared machines. Often a direct regulatory breach (GDPR/HIPAA/PCI).
- **Integrity**: stale cached content can mask legitimate updates (e.g., showing a revoked-role page) — lower severity.
- **Availability**: minimal, though cache poisoning can serve wrong content at scale.
- Severity scales with data sensitivity and shareability of the cache: a public CDN leaking one user's data to all requesters of that URL is critical; a single shared workstation is medium.

## Remediation
Set non-caching headers on every authenticated/sensitive response, and write temp files with restrictive, non-enumerable handling:
```ts
// VULNERABLE — sensitive JSON cached by default; temp file world-readable
app.get('/profile', (req, res) => res.json(user));
app.get('/export', async (req, res) => {
  const buf = await renderReport(req.user.id);
  await fs.writeFile(`/app/public/report_${req.user.id}.pdf`, buf); // static-served
  res.redirect(`/report_${req.user.id}.pdf`);
});

// SAFE — no-store on sensitive routes; private temp file, streamed and unlinked
app.get('/profile', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private')
     .set('Pragma', 'no-cache')
     .set('Expires', '0')
     .json(user);
});
app.get('/export', async (req, res) => {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'exp-'));      // 0700 dir
  const file = path.join(tmp, 'report.pdf');
  await fs.writeFile(file, await renderReport(req.user.id), { mode: 0o600 });
  res.set('Cache-Control', 'no-store').download(file, 'report.pdf', async () => {
    await fs.rm(tmp, { recursive: true, force: true });              // cleanup
  });
});
```
Defense-in-depth: scope CDN/reverse-proxy cache keys to include the session cookie or a per-user surrogate key, and never enable page caching for HTML/JSON behind authentication. Configure a global `no-store` default for authenticated routes and opt *in* to caching only for verified-public assets.

## References
- OWASP ASVS V8.1.x (data protection at rest/in transit) and V8.2.x (sensitive data, caching) — sensitive data must not be cached on shared infrastructure.
- OWASP WSTG-CRYP-01 — review of cached/temporary sensitive data; WSTG-ATHN-06 — browser cache testing for authenticated content.
- OWASP Cheat Sheets: Sensitive Data, Caching, Session Management.
