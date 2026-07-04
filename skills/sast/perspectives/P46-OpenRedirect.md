---
id: P46
name: OpenRedirect
area: V1 Encoding and Sanitization
refs: ASVS V5.3.x / WSTG-INPV-12 / CS: Unvalidated Redirects and Forwards
---

# P46 — Open Redirect

## Overview
An open redirect occurs when a server-side redirect target (`Location` header, redirect response, server-side or client-side forward) is derived from **unvalidated request input** — a query parameter (`next`, `url`, `redirect_uri`, `returnTo`, `callback`, `to`), a form field, or a header — and the application issues the redirect without confirming the destination is an allow-listed or same-origin target. Unlike injection, no server data is directly corrupted; the value of the flaw is its use as a **trust amplifier**. Because the redirect originates from the legitimate, trusted domain, users (and downstream security controls) are far more likely to follow it, making the vulnerability a vehicle for phishing, OAuth token theft, SSRF chaining, and bypass of URL-based allow-lists. The root cause is uniformly the same: an untrusted string reaches a redirect sink through a code path that performs no origin/host validation, or that performs a validation easily defeated by parser confusion (protocol-relative URLs, `@`, percent-encoding, whitespace, or Unicode lookalikes).

## What to check
- Does any handler build a redirect (`res.redirect`, `redirect()`, `301/302/303/307/308`, `Location` header) from a request-controlled value (`req.query`, `req.params`, `req.body`, `req.headers.referer`, fragment from URL)?
- Is the destination validated against an **allow-list of trusted hosts** or restricted to **same-origin / known relative path** before the redirect? "Not starting with `http`" is not validation.
- Are parser-differential bypasses covered? Check for: protocol-relative `//evil.com`, backslash `\/evil.com`, `@` authority (`https://app.com@evil.com`), `javascript:`, `data:`, `vbscript:`, CRLF / `%0d%0a` header injection, leading whitespace/control chars, and Unicode look-alikes.
- In OAuth / OIDC / SAML / SSO flows, is the `redirect_uri` / `post_logout_redirect_uri` / `RelayState` / `target_link_uri` strictly validated against registered URIs *before* redirecting?
- Does the app accept an absolute URL where a path was expected, or treat a leading `/` as "internal" without checking for `//` (which browsers send off-site)?
- Are redirects used to "bounce" to a user-supplied file/image URL (avatar, export, proxy endpoint) — possible SSRF if fetched server-side, or open redirect if just bounced?
- Does the app forward an unvalidated `next` parameter across multiple internal redirects, propagating the taint past a check that only sees a relative-looking fragment?

## Static signals
Direct reflection of request input into a redirect sink:
- Node/Express: `res.redirect(req.query.next)`, `res.redirect(req.body.url)`, `res.redirect(req.headers.referer)`, `res.set('Location', req.query.to)`
- Python/Django: `redirect(request.GET.get('next'))`, `HttpResponseRedirect(url)`, `HttpResponse(status=302, headers={'Location': url})`
- Python/Flask: `return redirect(request.args.get('next'))`
- Java/Spring: `return "redirect:" + next;`, `response.sendRedirect(url)`, `response.setHeader("Location", url)`
- Go: `http.Redirect(w, r, r.URL.Query().Get("next"), 302)`, `w.Header().Set("Location", url)`
- PHP: `header("Location: " . $_GET['next']);`, `return redirect(request()->input('url'))` (Laravel)
- Ruby/Rails: `redirect_to params[:return_url]`, `redirect_to request.referer`
- C#/ASP.NET: `return Redirect(Request.Query["returnUrl"]);`, `Response.Redirect(url)`

Allow-list/origin checks that are absent or trivially bypassable:
- `if url.startsWith('/')` — defeated by `//evil.com` (protocol-relative)
- `if !url.startsWith('http')` — defeated by `//evil.com`, `javascript:`, `data:`
- `if 'app.com' in url` — defeated by `evil.com?app.com` or `evil-app.com.attacker.tld`
- `new URL(url).hostname.endsWith('app.com')` — defeated by `attackerapp.com`
- `url.replace('app.com', '')` style sanitization

OAuth/SSO parameters handled loosely:
- `redirect_uri`, `post_logout_redirect_uri`, `target_link_uri`, `RelayState`, `returnTo`, `callback`, `continue`, `dest`, `ru` reflected without exact registered-URI match.

## False positives
- The destination is a **hardcoded internal path** or selected from a server-side `enum`/`switch` of known strings — no request input reaches the sink.
- The destination is validated with an **exact, registered-URI allow-list** (OAuth `redirect_uri` exact or strict scheme/match), or restricted to `same-origin` via `new URL(url, base).origin === base` *and then only the pathname is used*.
- The redirect target is server-generated (e.g., a signed token, a row from the DB the user already owns), not directly attacker-influenced.
- Internal-only route reachable solely post-authentication, redirecting to another internal route — low/none (note: still verify no off-site breakout via `//`).
- The value is normalized and re-checked after resolving relative URLs; parser-differential bypasses have been considered and rejected.

## Attack scenario
1. The app has a login flow: `GET /login?returnTo=...` → after auth, `res.redirect(req.query.returnTo)`.
2. Attacker crafts `https://app.example.com/login?returnTo=//evil.example.com/phish` and emails it to an employee. The `//` is protocol-relative; the host check (if any) saw a path-like string.
3. The victim, recognizing the legitimate `app.example.com` domain, authenticates normally.
4. The server issues `302 Location: //evil.example.com/phish`. The browser resolves it off-site to `https://evil.example.com/phish`, which presents a re-login form.
5. The victim re-enters credentials, handing them to the attacker. In an OAuth variant, the attacker uses the same vector to capture an authorization `code`/`access_token` redirected to their controlled `redirect_uri`.

## Impact
- **Confidentiality**: OAuth/OIDC authorization codes and tokens stolen via malicious `redirect_uri`; credentials phished; Referer-based secrets leaked to the off-site destination.
- **Integrity**: victims tricked into installing malware or approving actions on attacker-controlled pages masquerading as the trusted app.
- **Availability**: usually indirect, but usable to drive victims to drive-by/malware distribution or DoS a downstream service via SSRF chaining.
- Severity scales with context: a redirect inside an OAuth grant flow (token theft → account takeover) is High; a generic post-login bounce used only for phishing is Medium; an authenticated-only internal-only bounce with no off-site reach is Low.

## Remediation
Validate the destination against an allow-list and redirect only to the verified path:
```ts
// VULNERABLE — request input directly to the redirect sink
app.get('/login', auth, (req, res) => res.redirect(req.query.returnTo));

// SAFE — same-origin check, then redirect only to the pathname
app.get('/login', auth, (req, res) => {
  const base = `${req.protocol}://${req.get('host')}`;
  const next = req.query.returnTo ?? '/';
  let url;
  try { url = new URL(next, base); } catch { return res.status(400).end(); }
  if (url.origin !== base) return res.status(400).end();
  res.redirect(url.pathname + url.search + url.hash);
});
```
For OAuth flows, validate `redirect_uri` against the exact registered URIs server-side; never rely on client-supplied or substring matching. As defense-in-depth, attach a short-lived signed/HMAC token to the `returnTo` value so that off-list or tampered destinations are rejected, and set a restrictive `Referrer-Policy` to limit leakage of tokens in Referer headers across the redirect.

## References
- OWASP ASVS V5.3.x — Input validation and output encoding (unvalidated redirects)
- OWASP WSTG-INPV-12 — Testing for Open Redirect
- OWASP Cheat Sheet: Unvalidated Redirects and Forwards
