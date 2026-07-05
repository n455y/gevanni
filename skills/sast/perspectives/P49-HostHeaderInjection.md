---
id: P49
name: HostHeaderInjection
refs: ASVS V5.3.x, V7.x.x / WSTG-INPV-12, WSTG-INPV-17 / CS: Header Injection, Email Injection, Forgot Password Cheat Sheet
requires: [backend]
---

# P49 — HostHeaderInjection

## Overview
Host Header Injection is the abuse of client-controlled HTTP request headers — chiefly `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, and `Referer` — that the application implicitly trusts when building URLs, links, redirects, or mail content. The server's `Host` header is attacker-controllable unless a trusted reverse proxy overwrites it; `X-Forwarded-*` headers are even more so because any client can forge them. The root cause is twofold: (1) using raw header values to derive absolute URLs (password-reset links, OAuth callbacks, cache keys) and (2) placing newline-containing user input into email recipients, subjects, or headers, which lets a `\r\n` sequence smuggle extra headers (Bcc, a second `To`, a `Reply-To`). Exploits range from password-reset poisoning and web-cache poisoning to mass mailer abuse and SSRF.

## What to check
- Does any handler build an absolute URL from `req.headers.host`, `x-forwarded-host`, `x-forwarded-proto`, or `Referer` — especially in password-reset, email-verification, OAuth redirect, or "share this" features?
- Is the `Host` / `X-Forwarded-Host` value validated against an allow-list of expected domains before use?
- Does email sending accept request-controlled `to`/`cc`/`bcc`/`replyTo`/`subject`/`from` without rejecting CR/LF (`\r\n`, `%0d%0a`) and without enforcing a single RFC 5321/5322 address?
- Are trusted proxy headers (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Real-IP`) consumed for access control, rate-limit keys, or redirect target without confirming the proxy chain is pinned and the framework is configured to trust only known hops?
- Is the `Host` header used as a cache key (e.g. via a CDN that does not normalize it), enabling cache poisoning?
- Do redirects use the header to compute a `Location` (`res.redirect`, `Location:` header) leading to open redirect?
- Are logging/audit entries that embed the header susceptible to log injection (CRLF, fake log lines)?

## Static signals
URL construction from request headers:
- Node/Express: `` `${req.headers.host}/reset?t=${token}` ``, `req.get('host')`, `req.get('x-forwarded-host')`, `req.protocol` (which respects `X-Forwarded-Proto`)
- Python/Flask: `request.headers['Host']`, `request.host`, `request.host_url`, `url_for(..., _external=True)` (uses Host)
- Python/Django: `request.get_host()` (SAFE only if `ALLOWED_HOSTS` is set; vulnerable if `DEBUG=True` or allow-list is `*`)
- Java/Spring: `request.getHeader("host")`, `ServletServerHttpRequest`, `UriComponentsBuilder.fromHttpUrl(...)`
- Go: `r.Host`, `r.Header.Get("X-Forwarded-Host")`
- PHP: `$_SERVER['HTTP_HOST']`, `$_SERVER['SERVER_NAME']`, `getenv('HTTP_HOST')`
- Ruby/Rails: `request.host`, `request.headers['X-Forwarded-Host']`, `url_for(action: ..., host: request.host)`

Email injection (newline smuggling):
- `nodemailer.sendMail({ to: req.body.to, subject: req.body.subject, ... })` with no sanitization
- Python `smtplib`: `smtp.sendmail(from, to, msg)` where `msg`/`to`/`from` contain user input
- PHP `mail($to, $subject, $message, $headers)` — classic header injection vector
- Ruby `Mail`: `Mail.deliver(to: params[:email], subject: params[:subject])`
- Java `jakarta.mail` / Spring `JavaMailSender` building `MimeMessage` from request fields
- Grep for `req.body.email`, `req.body.to`, `params[:email]` flowing into mailer calls; for `\r`, `\n`, `%0d`, `%0a` checks that are absent

Trusted-proxy misconfiguration:
- Express `app.set('trust proxy', true)` (trusts ALL hops) instead of an explicit hop count / IP list
- Django `SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')` without a fronting proxy that strips client-supplied values
- Spring `server.forward-headers-strategy: native` behind an unconfigured proxy

## False positives
- A trusted reverse proxy (nginx, AWS ALB, Cloudflare) overwrites `Host` and strips client-supplied `X-Forwarded-*` before the app sees them — risk drops to Medium/Low but still verify the proxy actually rewrites rather than appends.
- `request.get_host()` in Django with a strict `ALLOWED_HOSTS` allow-list rejects spoofed hosts, neutralizing the URL vector.
- Email recipients are validated with a strict single-address RFC parser (e.g. `email_validator`, `validator.isEmail`) that rejects embedded newlines and display names — recipient/header injection is then mitigated.
- The header value is only used to pick from a hardcoded map of allowed hosts (allow-list dispatch), not interpolated into a string.
- The mail library escapes CRLF internally (rare; verify in framework docs before dismissing).

## Attack scenario
1. Attacker requests a password reset for a victim account but sends a crafted `Host` (or `X-Forwarded-Host`) header: `Host: evil.com`.
2. The app generates a reset link using the attacker-controlled host: `https://evil.com/reset?t=SECRET_TOKEN` and emails it to the victim.
3. The victim clicks the link in the email; the token leaks to `evil.com`.
4. Attacker replays the token against the real application and takes over the account.

Email-injection variant:
1. A contact form passes `req.body.email` straight into `mail($to=..., $headers="From: $email")`.
2. Attacker submits `email = "victim@x.com%0d%0aBcc: list@target1,list@target2%0d%0aSubject: ..."` — the `%0d%0a` (CRLF) injects a `Bcc` and many extra recipients.
3. The server's mailer becomes an open spam relay, damaging sender reputation and potentially exfiltrating bounce data.

## Impact
- **Confidentiality**: password-reset / email-verification token leakage → account takeover; mass spam / phishing from the server's domain.
- **Integrity**: cache poisoning (other users served attacker-controlled content), open redirect to phishing sites, injected mail headers misleading recipients.
- **Availability**: mail-provider suspension from spam volume; cache flooding.
- Severity scales with the feature: reset-link poisoning is typically High (full account takeover); cache poisoning in a shared CDN can be Critical; header-based open redirect is Medium.

## Remediation
Derive URLs from a server-side configuration constant, never from request headers; validate mail fields strictly:
```ts
// VULNERABLE — Host-derived reset link + unsanitized email fields
const link = `${req.headers.host}/reset?t=${token}`;
mailer.sendMail({ to: req.body.to, subject: req.body.subject });

// SAFE — fixed base URL + strict single-address validation
const link = `${CONFIG.appBase}/reset?t=${token}`;
const to = parseSingleAddress(req.body.to); // rejects CRLF, multiple addrs
if (!to) return res.status(400).send('invalid address');
mailer.sendMail({ to, subject: 'Reset your password' });
```
Defense-in-depth: configure the reverse proxy to overwrite (not append) `Host`/`X-Forwarded-*`, set a strict `ALLOWED_HOSTS` (Django) / `trust proxy` hop list (Express), and enforce a single-RFC-address parser with CRLF rejection at every mail boundary.

## References
- OWASP ASVS V5.3.x — Output encoding / injection prevention; ASVS V7.x.x — Communications and email security
- OWASP WSTG-INPV-12 — Testing for Host Header Injection; WSTG-INPV-17 — Testing for Host Header Injection (cache poisoning)
- OWASP Cheat Sheets: Header Injection, Email Injection, Forgot Password Cheat Sheet, HTTP Strict Transport Security
