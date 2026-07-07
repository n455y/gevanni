---
id: P131
name: EmailHeaderInjection
refs: ASVS V1.x / WSTG-INPV / CS: Injection Prevention
---

# P131 — EmailHeaderInjection

## Preconditions

The code sends emails.


## Overview
Email header injection occurs when user-controlled input placed into an email header field — `to`, `cc`, `bcc`, `from`, `reply-to`, `subject`, or custom headers — contains CR/LF sequences (`\r\n`, `\n`) that the mailer does not strip. Because RFC 5322 delimits headers with a blank CRLF line and individual headers with CRLF, an embedded newline lets the attacker terminate the intended header and append arbitrary new headers — additional `To`/`Bcc` recipients, a new `Subject`, a second `Content-Type`, or even a fresh message body after a blank line. The root cause is always the same: untrusted data reaches a low-level mail API that treats the value as raw header text, with no structural validation or normalization of line terminators.

## What to check
- Does any handler feed request-derived data (`req.body`, `req.query`, form fields) into a mailer call as `to`, `cc`, `bcc`, `from`, `replyTo`, `subject`, or into a custom `headers` map?
- Are addresses validated against a real RFC 5322 grammar (or at minimum an allow-list regex) *before* being passed to the mailer, or is the raw string forwarded?
- Is the `subject` line built by concatenating user input without stripping CR/LF? Newlines in subjects inject trailing headers.
- For Python `smtplib.sendmail` / `email.message`: is the message assembled by hand (string concatenation of headers) rather than via a structured `EmailMessage` with `.add_header()`? `sendmail` performs **no** header validation.
- For PHP `mail()`: is the fourth argument (`additional_headers`) or fifth (`additional_params`) built from user input? `mail()` does not escape embedded newlines in PHP < 5.2.15 / 5.3.3; later versions still permit it depending on build and `mail.add_x_header`.
- For JavaMail (`jakarta.mail`/`javax.mail`): are addresses added with `InternetAddress(addr)` (which validates/parses) or with raw string `setHeader`/`addHeader` calls?
- For Go `net/smtp.SendMail`: the `to` slice and message bytes are sent verbatim — any newline in an address or header field is injected.
- For Ruby `Mail`: is `Mail.new` used with structured fields, or are headers set via `mail['X-Foo'] = user_input`?
- Does the app accept a comma-separated recipient list and split it on `,` without then validating each element (allowing `\r\n` inside one element)?
- Are templated headers (`In-Reply-To`, `Message-ID`, `Return-Path`, custom tracking headers) populated from user input or DB values that originated from user input?
- Does the mailer configuration (e.g. nodemailer) disable any built-in validation, or pass `disableFileAccess`/`disableUrlAccess`-style flags that also relax header checks?

## Static signals
Hand-built message strings / header concatenation:
- Node: `nodemailer` `transport.sendMail({ to: req.body.email, subject: 'Hi ' + req.body.name, ... })` where `email`/`name` are unvalidated
- Node: `` `From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\n\r\n${body}` `` built manually for `smtpServer`/raw socket send
- Python: `smtplib.SMTP(...).sendmail(from, to, "From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s" % (f, t, subj, body))`
- Python: `email.message.Message()` followed by string-built header via `msg.as_string()` after manual `\r\n` joins
- PHP: `mail($to, $subject, $msg, "From: $_POST[email]")` — classic fourth-argument injection
- PHP: `mail($_POST['to'], $_POST['subject'], ..., '-f' . $_POST['from'])` (fifth arg, envelope sender)
- Java/JSP: `message.setHeader("Reply-To", request.getParameter("email"))` instead of `setReplyTo(new InternetAddress(...))`
- Go: `smtp.SendMail(addr, auth, from, []string{to}, []byte("To: "+to+"\r\n..."))`
- Ruby: `mail['X-User'] = params[:user]`

Validation gaps (signals to look for as missing controls):
- Address fields reaching mailer with no `isEmail()`/`validator.isEmail`/`EmailValidator`/`InternetAddress().validate()` gate
- `subject` value never passed through `replace(/[\r\n]/g, '')` or equivalent normalization
- Custom header keys/values built from `req.body` keys (e.g. iterating `Object.entries(req.body)` into `headers`)

## False positives
- The mailer library enforces strict RFC parsing on the field: nodemailer validates `to`/`from` via `mailparser`/`address-rfc2822` and rejects malformed addresses (confirm the version — early 1.x did not); JavaMail `InternetAddress(...)` with `validate()` throws on bad input.
- Recipient values are server-generated (e.g. `user.email` loaded from a verified DB column) and never echoed from the request verbatim.
- The app sends a templated newsletter where `to` is a fixed internal list and only the body (not headers) contains user data — header injection needs a header field, not body content.
- Input was validated against a strict allow-list (single address matching a conservative regex with no `\r`/`\n`) before reaching the mailer.
- The transport is a transactional API (SendGrid/SES/Postmark via HTTP) that takes structured JSON fields and rejects embedded newlines server-side — even then, verify the SDK does not stringify the field before sending.

## Attack scenario
1. The app has a "tell a friend" form that posts `{ email, message }` and the handler runs `sendMail({ to: email, subject: 'Invite' })` with no address validation.
2. Attacker submits `email = "victim@example.com\r\nBcc: ceo@target.com, investor1@x.com, investor2@x.com"`.
3. The mailer emits `To: victim@example.com<CRLF>Bcc: ceo@target.com, ...` — the Bcc line becomes a real header, silently adding recipients invisible to the primary `To`.
4. Scale it: the attacker submits thousands of addresses via `Bcc`/additional `To` headers, turning the application into an open spam relay sent from the company's trusted, DKIM-signed domain — high deliverability, likely bypassing recipient spam filters.
5. Variant: inject a blank line followed by a new `Content-Type: text/html` and a forged body to send phishing from the app's own address, or inject a `Reply-To: attacker@evil.com` so replies to "official" mail flow to the attacker.

## Impact
- **Confidentiality**: Bcc exfiltration of internal/private recipient lists; leakage of message content to attacker-controlled addresses.
- **Integrity**: arbitrary additional recipients, forged subject/body, phishing sent from the application's trusted domain.
- **Availability**: the app's mail domain/IP can be blacklisted (spam/abuse), degrading or blocking legitimate outbound mail for all users.
- Severity scales with the mailer's trust (DKIM/SPF alignment makes the spam/phishing far more convincing), the volume the endpoint allows, and whether recipients include privileged accounts (staff, executives). Open-relay abuse can exhaust the provider's quota and cause sustained outbound-mail outage.

## Remediation
Validate every header-bound field with a strict address/grammar check and strip CR/LF; prefer structured mailer APIs over hand-built message strings:
```ts
// VULNERABLE — raw user input straight into headers
transport.sendMail({
  to: req.body.email,                                  // attacker: "x@y\r\nBcc: leak@evil"
  subject: 'Invite from ' + req.body.name,             // newline in name injects headers
  text: req.body.message,
});

// SAFE — validate address + sanitize free-text header fields
import validator from 'validator';

function safeHeaderField(v: string): string {
  return String(v).replace(/[\r\n]/g, ' ').trim();
}

const to = safeHeaderField(req.body.email);
if (!validator.isEmail(to)) return res.status(400).send('invalid address');

transport.sendMail({
  to,                                                  // validated single address
  subject: safeHeaderField('Invite from ' + req.body.name),
  text: req.body.message,                              // body is fine; headers are the risk
});
```
Apply the same CR/LF stripping to `cc`, `bcc`, `from`, `replyTo`, and every value placed in a custom `headers` map. Defense-in-depth: enforce a server-side recipient rate limit per IP/account and prefer a transactional mail API (SendGrid/SES) that takes structured fields, so even a missed validation cannot reach a raw SMTP socket.

## References
- OWASP ASVS V1.x — Input validation, encoding and injection prevention
- OWASP WSTG-INPV — Testing for Input Validation / Injection (header injection cases)
- OWASP Cheat Sheet: Injection Prevention (Email/SMTP header injection guidance)
