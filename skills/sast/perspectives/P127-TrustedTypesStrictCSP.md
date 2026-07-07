---
id: P127
name: TrustedTypesStrictCSP
refs: ASVS V3.x / WSTG-CLNT / CS: Content Security Policy, DOM based XSS Prevention
---

# P127 — TrustedTypesStrictCSP

## Preconditions

The code sets Content Security Policy.


## Overview
Content Security Policy (CSP) and Trusted Types are the last structural defenses against cross-site scripting once an encoding bug, a misconfigured template, or a vulnerable client-side dependency lets attacker-controlled markup reach the DOM. A permissive policy — `unsafe-inline`, `unsafe-eval`, or `script-src *` — makes the header cosmetic: any injection becomes executable script. Trusted Types goes further by **removing the dangerous string sinks entirely** (`innerHTML`, `outerHTML`, `document.write`, `eval`, `insertAdjacentHTML`, attribute sinks) and requiring a typed policy object before the browser will accept markup. The root cause of findings here is always a policy that ships loopholes (JSONP endpoints, Angular template expressions, upload-hosted scripts, missing nonces/hashes) or a codebase that touches DOM sinks directly without enforcing Trusted Types, so a single future `innerHTML = userInput` cannot be blocked.

## What to check
- Is a CSP header actually emitted for **every** HTML response (`Content-Security-Policy`, not the report-only variant that does nothing), and is it set via a hard-to-tamper transport (HTTP response header / `<meta>` with no `unsafe-`)?
- Does `script-src` (or `default-src`) contain `unsafe-inline` or `unsafe-eval`? Either largely neutralizes the policy. Note `'unsafe-inline'` is ignored by the browser as soon as a nonce or hash is present — confirm which is in force.
- Are scripts loaded with **nonces** (`'nonce-<random>'`, server-generated per request) or **hashes** (`'sha256-...'` of inline content)? A static, hardcoded "nonce" reused across requests is not a nonce.
- Is the origin allow-list overly broad — `*`, `https:`, CDNs that host user-uploaded content, or third-party origins that allow JSONP / callback endpoints (`cdn.com/api?cb=...`) that an attacker can abuse as a script-injection oracle?
- Are upload hosts or static asset buckets (e.g. `*.cloudfront.net`, `s3.amazonaws.com/bucket`) listed in `script-src` or `object-src`? If users can upload `.js`/`.html`/`.svg` there, they can bypass the CSP.
- Is Trusted Types actually enforced (`Content-Security-Policy: require-trusted-types-for 'script'; trusted-types <policies>`), or only `Content-Security-Policy-Report-Only`? A report-only header does not block sinks at runtime.
- Are DOM XSS sinks called with raw strings instead of policy-created `TrustedHTML`/`TrustedScriptURL` values — `el.innerHTML = ...`, `document.write`, `insertAdjacentHTML`, `eval`, `new Function`, `setTimeout("...")`, `setAttribute('onclick', ...)`, jQuery `.html()`, Angular/Dompurify bypasses?
- Are Angular/AngularJS template expressions (`{{ }}`) reachable where attacker input is interpolated client-side, enabling CSP bypass via prototype / sandbox-escape techniques independent of `script-src`?
- Are trusted-type policies created from attacker-controlled data, or does a policy wrap unsanitized input (e.g. `policy.createHTML(userInput)` without DOMPurify)? A policy that does not sanitize is a hole, not a defense.
- Does the policy's reporting endpoint (`report-uri` / `report-to`) actually exist and is monitored, or are violations silently lost?

## Static signals
Dangerous DOM sinks reached with raw strings (Trusted Types would block these):
- `el.innerHTML = userInput`, `el.outerHTML = ...`, `document.body.innerHTML += ...`
- `document.write(...)`, `document.writeln(...)`
- `el.insertAdjacentHTML('beforeend', ...)`
- `eval(str)`, `new Function(str)`, `setTimeout(str, ...)`, `setInterval(str, ...)`, `window.execScript`
- `el.setAttribute('on*' , ...)` (event handler attributes), `script.text = ...`, `script.src = userInput`
- jQuery: `$(...).html(str)`, `$.parseHTML`, `$(str)` with a leading `<`
- Angular: `[innerHTML]="..."` bypassing `DomSanitizer`; raw `bypassSecurityTrustHtml(...)`
- React: `dangerouslySetInnerHTML={{ __html: ... }}`; Vue `v-html`; Svelte `{@html ...}`

Loophole CSP (grep headers / meta tags / config):
- `Content-Security-Policy` containing `script-src ... 'unsafe-inline'`, `'unsafe-eval'`, `*`, `https:`, `data:`
- `default-src *` / `default-src 'none'` overridden by `script-src *`
- Hardcoded static "nonce" in source: `nonce="abc123"` reused on every render (not random per request)
- `require-trusted-types-for` absent, or present only under `Content-Security-Policy-Report-Only`
- `trusted-types *` (allows any policy name — weakens auditability)
- Origin allow-list includes upload/S3/CDN hosts, or JSONP-capable endpoints

Config-file / server snippets:
- Node/helmet: `helmet.contentSecurityPolicy({ directives: { scriptSrc: ["'unsafe-inline'", ...] }})`
- Next.js `next.config.js` `headers()` returning a CSP with `unsafe-eval`
- nginx `add_header Content-Security-Policy "script-src 'self' 'unsafe-inline'";`
- Meta: `<meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-eval'">`

## False positives
- `'unsafe-inline'` in the policy **and** a nonce/hash present — browsers ignore the inline directive, so it is not an active bypass. Still flag it as hygiene, not as a vulnerability.
- `report-only` headers during staged rollout are intentional; downgrade severity but confirm a plan to enforce.
- A genuinely sandboxed iframe sandbox with `allow-scripts` but no `allow-same-origin` can safely run inline scripts; its parent CSP may be irrelevant to that frame.
- Trusted Types is enforced but a sink is fed by a correctly created, sanitized policy value (`policy.createHTML(DOMPurify.sanitize(x))`) — the defense is working as intended.
- Strict static allow-lists (e.g. `script-src 'self' 'nonce-...'` with no CDN/upload hosts) leave essentially no bypass; the policy is strong even if a minor injection exists.

## Attack scenario
1. Recon: attacker finds a reflected/DOM XSS sink (`search#q=` reaching `el.innerHTML = decodeURIComponent(hash)`) and reads the CSP: `script-src 'self' 'unsafe-inline' https://cdn.app.com`.
2. Because `'unsafe-inline'` is present **without** a nonce, an injected `<script>` executes directly — no further work needed.
3. Even if the team later removes `unsafe-inline`, attacker pivots: `cdn.app.com` hosts user uploads (or a JSONP endpoint `https://cdn.app.com/api?callback=alert(1)`). They inject `<script src="https://cdn.app.com/uploads/evil.js">`, satisfying `'self'`-adjacent origin rules.
4. Alternatively, on an AngularJS app with CSP `script-src 'self'`, attacker injects `{{constructor.constructor('alert(document.cookie)')()}}`; the client-side template engine evaluates it without a `<script>` tag, sidestepping `script-src`.
5. Without Trusted Types, none of the sinks (`innerHTML`, `eval`) are blocked at the engine level — every encoded output is only as safe as the last developer who remembered to sanitize.
6. With `require-trusted-types-for 'script'` enforced and a strict `script-src 'self' 'nonce-<rand>'`, steps 1–4 fail at runtime: the inline script, the upload-hosted script, and the unsanitized `innerHTML` all throw `TypeError` before executing, and the violation fires a report.

## Impact
- **Confidentiality**: full session/token theft, exfiltration of any DOM-accessible data (tokens in `localStorage`, form values, rendered PII).
- **Integrity**: arbitrary script in the victim's session — account takeover, fraudulent transactions, tampering with displayed data.
- **Availability**: page defacement, forced logout/redirect, crypto-mining or scareware payloads.
- Severity scales with victim privileges and with how permissive the policy is: `unsafe-inline`+`unsafe-eval` means a single injection = RCE-equivalent in the browser; a strict nonce+Trusted-Types posture downgrades most XSS to a noisy report.

## Remediation
Eliminate the loopholes and let the browser enforce DOM sinks:
```ts
// VULNERABLE — permissive CSP, raw innerHTML
// header: Content-Security-Policy: script-src 'self' 'unsafe-inline'
el.innerHTML = userInput;                       // executes attacker markup

// SAFE — strict CSP + Trusted Types
// header (set per-response by the server):
//   Content-Security-Policy:
//     script-src 'self' 'nonce-<per-request-random>';
//     object-src 'none'; base-uri 'none';
//     require-trusted-types-for 'script';
//     trusted-types sanitizeHTML;
//     report-to csp-endpoint;
const policy = trustedTypes.createPolicy('sanitizeHTML', {
  createHTML: (s) => DOMPurify.sanitize(s),     // only sanctioned sink entry
});
el.innerHTML = policy.createHTML(userInput);    // typed value; raw strings throw
```
Generate nonces server-side per request (crypto-random, base64) and inject into both the header and every `<script>` tag; never hardcode a nonce. Defense-in-depth: combine strict CSP + Trusted Types with framework auto-escaping and DOMPurify for any rich-HTML feature, and monitor the report endpoint so a regression surfaces before an attacker does.

## References
- OWASP ASVS V3.x — Frontend security, output encoding, and client-side injection controls
- OWASP WSTG-CLNT — Client-side testing (CSP, DOM sinks, Trusted Types)
- OWASP Cheat Sheets: Content Security Policy, DOM based XSS Prevention, Third Party Javascript Management
