---
id: P124
name: PostMessageOrigin
area: V3 Web Frontend Security
refs: ASVS V3.x / WSTG-CLNT / CS: HTML5 Web Messaging
requires: [frontend]
---

# P124 — PostMessageOrigin

## Overview
`window.postMessage` is the browser-sanctioned channel for cross-origin communication between frames, popups, and workers. The API exposes two independent trust boundaries: the **targetOrigin** argument on `send` (which the browser uses to silently withhold the message if the receiver's origin does not match) and the **`event.origin`** field on `receive` (which the receiver must check before trusting the payload). When either side is mishandled — a wildcard `'*'` targetOrigin on the sender, or a missing/loose origin check on the receiver — a message built for one origin can leak to, or be accepted from, an attacker-controlled page. The root cause is almost always treating `postMessage` as a raw pipe instead of an authenticated, schema-validated protocol: the developer forgets that any window with a reference to theirs can call `postMessage`, and that `event.source` and `event.origin` are the only grounds for trust.

## What to check
- On the **sender**: is `postMessage` called with the literal `'*'` (or omitted) as `targetOrigin`? That delivers the payload to whatever origin happens to be loaded in the target frame at send time — including an attacker who navigated it after load.
- On the **receiver**: does the `message` handler verify `event.origin` against a **strict allow-list** of expected origins, or does it skip the check, substring-match (`origin.includes('example.com')`), regex against attacker-influenceable input, or compare only the protocol/host but not the port?
- Does the handler trust `event.source` or `event.origin` to be one of several first-party origins without an explicit constant set (e.g., accepts any `*.example.com` when only `app.example.com` is legitimate)?
- Is the message payload treated as **code or markup**? Look for `innerHTML = event.data`, `document.write`, `eval(event.data)`, `new Function(event.data)`, `setTimeout(event.data, ...)`, or framework sinks (`v-html`, `dangerouslySetInnerHTML`) fed from `event.data`.
- Is the payload deserialized into live objects (`JSON.parse` then dispatched to privileged methods) without a **schema/type check**? Missing `type`/`cmd` field validation lets any origin invoke any handler the switch statement exposes.
- Can a third-party iframe (ad SDK, OAuth popup, payment widget) reach the handler? If the handler gates sensitive actions (token relay, redirect, credential posting), a malicious frame can spoof the trusted message shape.
- Is the reply sent back via `event.source.postMessage(..., '*')`? The wildcard reply leaks the response to whatever origin the message actually came from — fine only if the response is non-sensitive.
- Are message ports (`MessageChannel`, `transfer` arrays) used without first authenticating the remote end? A transferred port inherits no origin guarantee.

## Static signals
Wildcard / missing targetOrigin on send (JS/TS):
- `someWin.postMessage(data, '*')`
- `someWin.postMessage(data)` (second arg omitted → treated as `'*'`)
- `iframe.contentWindow.postMessage(payload, window.location.origin)` — origin derived from attacker-controllable navigation, not a constant
- `event.source.postMessage(reply, '*')` (reply leak)

Missing or weak origin check on receive:
- `window.addEventListener('message', e => { /* uses e.data directly */ })` — no `e.origin` check at all
- `if (e.origin.indexOf('example.com') !== -1)` — substring match (subdomain/tld bypass: `example.com.evil.tld`)
- `if (e.origin.endsWith('example.com'))` — bypassable by `notexample.com`
- `if (e.origin === 'https://example.com')` missing port (matches default port only; misses explicit `:443` or `:8443` cases)
- `if (e.isTrusted)` used as the sole gate — `isTrusted` reflects user gesture, not origin

Payload routed into sinks:
- `el.innerHTML = e.data` / `el.outerHTML = e.data`
- `document.body.insertAdjacentHTML('beforeend', e.data)`
- `eval(e.data)` / `new Function(e.data)()` / `setTimeout(e.data, 0)` / `setInterval(e.data, …)`
- `document.write(e.data)`
- Vue `v-html="msg"` / React `dangerouslySetInnerHTML={{ __html: msg }}` where `msg` came from `event.data`
- `$('<div>').html(e.data)` (jQuery — runs inline handlers)

Unvalidated dispatch on parsed payload:
- `const m = JSON.parse(e.data); switch (m.action) { ... }` — no `action` allow-list, no schema validation
- `window[m.cmd](m.arg)` — property-access dispatch into global functions

## False positives
- The handler genuinely does not exist for sensitive data and the message carries only UI hints (scroll position, theme toggle) — low impact, but still verify the wildcard send isn't leaking tokens.
- `targetOrigin` is `'/'` for a same-origin iframe sandbox or a hard-coded `https://app.example.com` constant — correct usage.
- The origin check uses a normalized `URL` parse (`new URL(e.origin).origin === EXPECTED`) and an explicit constant allow-list — that is the safe pattern, not a finding.
- The page is fully sandboxed (`<iframe sandbox>` with no `allow-scripts`), so injected script cannot run — but confirm the parent still validates origin, as `postMessage` is permitted even under some sandbox flags.
- A library (e.g., Stripe.js, Google Sign-In SDK) manages its own origin allow-list internally; the application code merely forwards a token to a known origin via a hardcoded `targetOrigin`.

## Attack scenario
1. The app embeds a first-party helper frame at `https://app.example.com/helper` and communicates with it via `parent.postMessage({ token }, '*')` (wildcard targetOrigin), or the parent accepts any message whose origin passes `origin.includes('example.com')`.
2. The attacker hosts `https://example.com.attacker.tld` (satisfies the substring check) or gets the helper frame navigated to an attacker page after load (exploiting the wildcard send).
3. The attacker page opens/iframes the app's parent and sends a crafted message shaped exactly like the trusted helper: `{ cmd: 'setRedirect', url: 'https://attacker.tld/' }` or `{ cmd: 'postCredentials' }`.
4. The parent's handler — lacking a strict origin allow-list and schema validation — honors the forged command: it redirects the user to a credential-harvesting page, leaks the session token back via `event.source.postMessage(token, '*')`, or executes attacker markup through `innerHTML = event.data`.
5. The attacker completes account takeover or DOM-based XSS in the victim's authenticated session, all without exploiting a server-side flaw.

## Impact
- **Confidentiality**: exfiltration of session tokens, user data, or cross-frame state leaked through wildcard replies or honored spoofed "send data" commands.
- **Integrity**: forged messages drive privileged client-side actions — redirect, post forms, modify account settings, execute arbitrary script if the payload reaches an HTML/eval sink.
- **Availability**: a spoofed message can lock the UI, force navigation away, or trigger infinite reload loops.
- Severity scales with what the message handler exposes: a handler that only relays a token or sets innerHTML is critical (account takeover / XSS); one that toggles a tooltip is informational. Wildcard `targetOrigin` on the sender is independently rated by the sensitivity of the payload being broadcast.

## Remediation
Always pin `targetOrigin` to a constant and validate origin with an allow-list plus schema on receive:
```ts
// VULNERABLE — wildcard send, no origin check, payload into innerHTML
iframe.contentWindow.postMessage({ html: userInput }, '*');
window.addEventListener('message', (e) => {
  document.getElementById('out').innerHTML = e.data;
});

// SAFE — constant targetOrigin, allow-listed origin, schema-validated, text sink
const HELPER_ORIGIN = 'https://app.example.com';
iframe.contentWindow.postMessage({ cmd: 'render', text: userInput }, HELPER_ORIGIN);

const ALLOWED = new Set(['https://app.example.com', 'https://cdn.example.com']);
window.addEventListener('message', (e) => {
  if (!ALLOWED.has(e.origin)) return;          // strict allow-list
  if (e.source !== iframe.contentWindow) return; // bind to expected frame
  let m: { cmd: string; text?: string };
  try { m = JSON.parse(e.data); } catch { return; }
  if (m.cmd !== 'render' || typeof m.text !== 'string') return; // schema gate
  document.getElementById('out').textContent = m.text;            // safe sink
});
```
Defense-in-depth: never route `event.data` into `innerHTML`/`eval`/`new Function` — use `textContent` or framework-safe sinks; apply a Content Security Policy (`script-src 'self'`) to cap damage if a handler is missed.

## References
- OWASP ASVS V3.x — Web frontend security and communication controls
- OWASP WSTG-CLNT — Client-side testing (HTML5 Web Messaging)
- OWASP Cheat Sheet: HTML5 Web Messaging
