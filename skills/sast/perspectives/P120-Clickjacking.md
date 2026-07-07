---
id: P120
name: Clickjacking
refs: ASVS V14.x / WSTG-CLNT / CS: Clickjacking Defense
---

# P120 — Clickjacking

## Preconditions

The code renders UI that can be framed.


## Overview
Clickjacking (UI redressing) occurs when an application can be embedded in a `<frame>`, `<iframe>`, or `<object>` by an attacker-controlled page, which then layers invisible or decoy UI on top to trick an authenticated victim into clicking or typing on the framed application's sensitive buttons/forms (delete, transfer, grant permissions, "like"). The root cause is not an input/output bug but a missing or permissive framing directive: the response carries no `X-Frame-Options` (XFO) header and no `Content-Security-Policy: frame-ancestors` directive (or sets them to permissive values like `ALLOW-FROM *`). Because the victim is interacting with their own legitimate session cookies, the action is authorized and bypasses most CSRF and XSS defenses. Mobile webviews and legacy browsers that ignore CSP compound the issue.

## What to check
- Does the app set **either** `X-Frame-Options` **or** CSP `frame-ancestors` on every HTML response (login pages, authenticated app, error pages, state-changing POST views)?
- Is the framing directive set to a restrictive value — XFO `DENY`/`SAMEORIGIN`, CSP `frame-ancestors 'none'`/`'self'` — rather than `ALLOW-FROM *` (deprecated/ignored) or a broad origin list?
- Are there cross-origin embeddable endpoints that perform state changes via GET (delete, unsubscribe, toggle) — prime likejacking / button-overlay targets?
- Does the app set `frame-ancestors` only on the root document but forget X-Frame-Options for legacy clients, or vice versa (defense should be layered; XFO is ignored by some agents, CSP by others)?
- Are interactive plugins/objects (`<object>`, `<embed>`, PDF/Flash viewers) framed without protection — CSP `frame-ancestors` also governs plugin documents?
- Is the header applied by a global middleware, or only on a subset of routes (e.g., static assets skipped, but a sensitive HTML route also skipped)?
- Does the app rely on JavaScript framebusting (`if (top !== self) top.location = self.location`) instead of headers? Framebusting is bypassable (sandbox iframe, X-Frame-Options on the attacker page) and should be defense-in-depth only.
- For interactive UIs, is `Cross-Origin-Opener-Policy`/sandboxing considered so a framed page cannot be scripted from the parent (defense for content hijacking)?

## Static signals
Header set permissively or absent (search response builders, middleware, web-server config):
- `X-Frame-Options: ALLOW-FROM *` / `ALLOW-FROM null` — `ALLOW-FROM` is deprecated and widely ignored
- `X-Frame-Options` not present anywhere, or only on `/login`
- `Content-Security-Policy` set but **without** a `frame-ancestors` directive
- `frame-ancestors *`, `frame-ancestors https:` (wildcard scheme), `frame-ancestors 'self' evil.com`

Node/Express:
```js
// VULNERABLE — no framing protection at all
app.get('/transfer', (req, res) => res.render('transfer'));

// WEAK — XFO only, missing CSP frame-ancestors (modern browsers prefer CSP)
res.set('X-Frame-Options', 'SAMEORIGIN');
```

Python (Django/Flask/FastAPI):
- Django: `X_FRAME_OPTIONS = 'DENY'` left at default `'SAMEORIGIN'` is acceptable; setting `@xframe_options_sameorigin` and forgetting `frame-ancestors` is a gap
- Flask: missing `flask_talisman`/`SecureHeaders`, or `Talisman(frame_options=...)` with no CSP `frame-ancestors`

Java/Spring:
- `X-Frame-Options` default in Spring Security is `DENY`, but custom `HttpSecurity(headers(h -> h.frameOptions(fo -> fo.sameOrigin().disable())))` weakens or removes it
- `<security:headers><security:frame-options disabled="true"/></security:headers>`

Go / Ruby / PHP:
- Go: `w.Header().Set("X-Frame-Options", ...)` absent; Caddy/nginx reverse proxy not adding it
- Rails: `config.action_dispatch.default_headers` lacking `X-Frame-Options`, or `protect_from_forgery` without frame protection
- PHP: `header('X-Frame-Options: GOFORIT')` (invalid), or hand-rolled CSP omitting `frame-ancestors`

Cloud/proxy config (nginx, Apache, CDN):
- nginx: no `add_header X-Frame-Options SAMEORIGIN;`, or `add_header` in a `location` block that overrides (not inherits) the server-level header
- Apache: `Header always set X-Frame-Options` missing; legacy `mod_headers` with `SAMEORIGIN` only
- CDN/WAF (Cloudflare, AWS CloudFront, ALB) response-header policy omitting XFO/CSP

JavaScript framebusting (weak, not a substitute):
```js
if (top.location !== self.location) { top.location = self.location; } // bypassable
```

## False positives
- The response is a non-HTML document (image, JSON API, font, downloadable file) — `frame-ancestors`/XFO are irrelevant for data consumed by code rather than rendered as a UI.
- The app is **intentionally** embeddable only by a tightly scoped allow-list of first-party origins and every embedder is trusted (rare; verify the list is minimal and not `*`).
- The header is applied at the reverse proxy / CDN / WAF layer rather than in application code — confirm it is present in the actual response (test, don't assume).
- A page legitimately uses iframes to embed **third-party** content; that concerns `frame-src`/`child-src`, not `frame-ancestors` (which controls who may frame *this* page).
- `frame-ancestors` reported missing by a scanner that only checked an API/JSON endpoint — re-check the HTML document endpoints.

## Attack scenario
1. Attacker hosts `evil.com` with a page containing `<iframe src="https://bank.example.com/transfer?to=attacker&amount=10000" style="opacity:0; position:absolute; z-index:99">`.
2. Over the invisible iframe, the attacker layers a decoy button labeled "Win a free phone!" positioned exactly over the framed "Confirm Transfer" button.
3. The victim, already authenticated to `bank.example.com`, is lured to `evil.com` and clicks the decoy.
4. The click lands on the real, invisible bank button; the victim's session cookie authenticates the request, and the transfer executes.
5. Variant — **likejacking**: an invisible "Like"/"Follow"/"Grant access" widget is overlaid on a video play button, harvesting consent or social actions.
6. Variant — **content/browser hijack via drag-and-drop or keystrokes**: framed form fields capture typed credentials, or a framed file-upload control swallows a dragged file.

## Impact
- **Integrity**: forged state-changing actions (transfers, deletes, privilege grants, OAuth scope authorization, account settings changes) executed as the victim — the dominant risk.
- **Confidentiality**: limited direct disclosure, but OAuth/consent clickjacking can grant an attacker long-lived access to victim data; keystroke capture can leak credentials typed into framed forms.
- **Availability**: framed UI can be abused to disable protections, delete data, or revoke recovery options.
- Severity scales with the exposed action's privilege: framing an admin-only confirmation page can enable full account takeover or data destruction; framing a public marketing page is negligible.

## Remediation
Send a restrictive framing directive on every HTML response; prefer CSP `frame-ancestors` (modern, multi-origin support) layered with `X-Frame-Options` for legacy clients:
```js
// VULNERABLE — embeddable by anyone
app.get('/transfer', (req, res) => res.render('transfer'));

// SAFE — layered framing defense
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});
```
For pages that must never be framed, use `frame-ancestors 'none'` with XFO `DENY`. Add a `SameSite=Lax|Strict` cookie attribute and require an CSRF token on state-changing requests as defense-in-depth — these don't prevent the click but bound what a hijacked click can authorize. JavaScript framebusting alone must never be relied upon.

## References
- OWASP ASVS V14.x — Configuration and client-side security (framing / CSP)
- OWASP WSTG-CLNT (Testing for Clickjacking, WSTG-CLNT-09 / Client-side testing)
- OWASP Cheat Sheet: Clickjacking Defense
