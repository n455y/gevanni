---
id: P130
name: ReverseTabnabbing
area: V3 Web Frontend Security
refs: ASVS V3.x / WSTG-CLNT / CS: HTML5 Web Application Security
---

# P130 — Reverse Tabnabbing

## Overview
Reverse tabnabbing (a.k.a. "tabnabbing via `target=_blank`") occurs when a page opens a link, popup, or new browsing context with `target="_blank"` (or `window.open`) **without** restricting the opener reference via `rel="noopener"` (and ideally `noreferrer`). In older browsers — and still today in some non-mainstream engines — the newly opened page holds a handle to its opener through `window.opener` and may call `window.opener.location = 'https://phishing.example/login'`, silently rewriting the original, authenticated tab. When the user switches back, they see a believable login prompt on what they trust as the real site and type credentials. The root cause is always the same: a navigable anchor or window-open call omits the opener-severing attributes, accepting as a target a fully or partially attacker-controlled URL.

## What to check
- Does any server-rendered template emit `<a ... target="_blank">` (or `_new`/`_top` to an external origin) **without** `rel="noopener noreferrer"` (or `rel="noopener"` on modern Chrome/Firefox)?
- Does client code call `window.open(url, ...)`, `window.open(url, '_blank')`, or assign to a new window's location while keeping a handle on `opener`?
- Are href targets derived from **user-controlled** sources — query params, profile fields, UGC, redirect-URL parameters, CMS content, comment bodies, ad creatives — and rendered into a `target=_blank` link?
- Are "external link" components (markdown renderers, rich-text editors, linkifiers) configured to add `target=_blank` but not to inject `rel="noopener"`? This is the classic markdown/`remark`/`react-markdown` misconfiguration.
- Does the app render third-party **advertising iframes** or sponsored-content widgets that navigate to advertiser URLs without sandboxing the opener relationship (`sandbox` attribute, `rel` on any link inside)?
- For `window.open` flows, is the returned handle used to call `.postMessage`, `.location =`, or `.focus()` against an untrusted/external target that can then pivot back via `opener`?
- On server-rendered pages, is there a global `<base target="_blank">` without a matching policy enforcing `rel`?
- Is the site served only to modern evergreen browsers where `target=_blank` implies `noopener` by default? (Safari, pre-88 Edge, and many embedded WebViews do **not** imply it — don't rely on implicit behavior.)

## Static signals
Anchor with `target=_blank` and no `noopener`:
- HTML: `<a href="<%= link %>" target="_blank">open</a>`, `<a target="_blank" href="{{ url }}">`
- EJS/Handlebars/Pug/Django template helpers that build the same tag.
- React/JSX: `<a href={url} target="_blank">` **without** `rel="noopener noreferrer"`.
- Vue: `<a :href="url" target="_blank">` without `:rel` or `rel`.
- Svelte/Angular: same pattern, `<a [href]="url" target="_blank">`.

`window.open` without opener severing:
- `window.open(url, '_blank')`, `window.open(url, '_blank', 'noopener')` — the third arg is the only way to pass `noopener` via `window.open`; bare two-arg calls leak `opener`.
- `const w = window.open(url); w.location = ...` — explicit opener-handle misuse.

Markdown / linkifier configs that inject `target=_blank` globally:
- `remark-rehype` with `target: '_blank'` but no `rel` rewriter.
- Python `markdown` / `markdown2` with `extra` or custom link extension setting `target` only.
- Ruby `Rinku`, PHP ` preg_replace`-based autolink adding `target="_blank"` without `rel`.
- `showdown`, `marked` (`{ target: '_blank' }` option, no `rel`).

Frameworks that historically imply `noopener` (verify version):
- React >= 17 auto-adds `rel="noopener"` only if `rel` is absent **and** `target="_blank"` is set — but adding *any* custom `rel` disables the auto-injection.
- Angular `[target]` does **not** auto-add `noopener` — explicit check needed.

## False positives
- The link target is **same-origin** and non-sensitive; cross-origin opener rewriting still works but impact is bounded. Still fix it for consistency, but it is not a credential-theft vector on its own.
- `target="_blank"` is combined with `rel="noopener"` (Chrome/Firefox/Edge ≥88) or `rel="noopener noreferrer"` — `opener` is severed; safe.
- The page is a static, unauthenticated landing page with no session to phish — reverse tabnabbing yields nothing useful, though adding `rel` remains best practice.
- `window.open` is called with the `'noopener'` feature string (`window.open(url, '_blank', 'noopener')`) — opener is null in the child.
- Iframes using `sandbox` without `allow-top-navigation` cannot rewrite the parent even if they hold the handle.

## Attack scenario
1. The vulnerable app renders a user profile field or a comment as `<a href="https://attacker.example" target="_blank">My site</a>` (no `rel`).
2. A victim (an employee/admin) clicks the link; the attacker's page opens in a new tab while the victim's authenticated session remains in the **original** tab.
3. The attacker page runs `if (window.opener) window.opener.location = 'https://login.example.com.evil.example/';` — the **original** tab silently navigates to a credential-harvesting clone.
4. The attacker tab can also blur itself and call `window.opener.focus()` to push the victim back to the now-fake login.
5. The victim, believing they were logged out, re-enters credentials into the cloned form; the attacker captures them and proxies or replays the login.

## Impact
- **Confidentiality**: credential theft via phishing of the original authenticated tab; leakage of the victim's session context if the cloned page is convincing.
- **Integrity**: the attacker gains the victim's account on the legitimate site once credentials are harvested — full account takeover, including admin accounts.
- **Availability**: minimal direct availability impact, but the trust-degradation and account compromise can cascade (admin lockout, fraud).
- Severity scales with the **privilege of the user who would click the link**: an end user loses one account; an admin or support agent whose tab is nabbed can compromise the whole tenant. Cross-origin reach makes external/UGC/ad links the highest-value entry points.

## Remediation
Always pair `target="_blank"` with `rel="noopener noreferrer"`; for `window.open`, pass `noopener` in the feature string:
```html
<!-- VULNERABLE — opener leaked -->
<a href="<%= profile_url %>" target="_blank">Visit my site</a>

<!-- SAFE — opener severed, referrer suppressed -->
<a href="<%= profile_url %>" target="_blank" rel="noopener noreferrer">Visit my site</a>
```
```js
// VULNERABLE — opener exposed to the opened page
window.open(untrustedUrl, '_blank');

// SAFE — feature string severs the opener
window.open(untrustedUrl, '_blank', 'noopener,noreferrer');
```
For markdown/rich-text pipelines, configure a link rewriter that forces `rel="noopener noreferrer"` on every external `target=_blank` link, and never render a user-supplied href into a new tab without an allow-listed scheme (`http`/`https` only). Defense-in-depth: serve a `Referrer-Policy: no-referrer` / `same-origin` header so referrer leakage is bounded even when `rel` is forgotten on a single link.

## References
- OWASP ASVS V3.x — Web Frontend Security (session, communication, and navigation controls)
- OWASP WSTG-CLNT — Client-side testing (reverse tabnabbing / `target=_blank`)
- OWASP Cheat Sheet Series: HTML5 Web Application Security / DOM-based XSS Prevention (opener and navigation hygiene)
