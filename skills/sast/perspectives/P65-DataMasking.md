---
id: P65
name: DataMasking
refs: ASVS V8.x / WSTG-CRYP-01, WSTG-CRYP-03 / CS: User Privacy Protections Implementation, Sensitive Data Exposure
---

# P65 — DataMasking

## Preconditions

The code displays or returns data.


## Overview
Data masking is the practice of truncating, redacting, or tokenizing sensitive fields — payment card numbers (PAN), government IDs (SSN, My Number), account numbers, API keys, secrets, and personal data — whenever they are **displayed to users, persisted in logs, or returned in bulk APIs**. The failure mode is not usually a missing crypto primitive but a missing rule: a handler returns the full PAN to the front end "because the screen needs it", or an error/log path serializes the raw secret for debugging. The root cause is treating masking as a UI concern instead of a server-side data-minimization control — the server should never emit more digits than the destination is authorized to see, and what it stores long-term should be tokenized or encrypted, not merely hidden in the view layer.

## What to check
- Are sensitive fields (PAN, SSN/My Number/Tax ID, IBAN, account number, phone, email, API key, private key) returned in full in any JSON/HTML response, list endpoint, export (CSV), or audit log?
- Is masking applied **server-side** before serialization, not delegated to the client? A `mask()` call in the React component still ships the raw value over the wire.
- Does the masking rule expose no more than the standard minimum (PCI DSS: max first 6 / last 4 of PAN; national-ID rules often allow last 4 only)? Are separators preserved or stripped consistently?
- Are full values logged anywhere — application logs, error/stack traces, debug endpoints, request/response body logging, audit trails, APM transaction traces (Sentry, Datadog), or outbound webhook payloads?
- Is long-term storage of the raw value avoided in favor of tokenization (vault-mapped surrogate) or field-level encryption with the key held separately?
- Do search/list endpoints return full sensitive columns to the client, or do they return only masked previews with a separate authorized "reveal" action?
- Are secrets (API keys, passwords, private keys) ever echoed in error messages, deserialization dumps, or `toString()`/`repr()` of objects that embed them?
- Does a "reveal full value" endpoint enforce step-up auth, authorization to that record, and audit logging of who saw what?

## Static signals
Returning raw sensitive fields unmasked:
- `res.json({ card: user.cardNumber })`, `res.json(user)` where `user` includes `ssn` / `pan`
- Python: `return jsonify(user.__dict__)`, `return Response(user.ssn)`, FastAPI `return user` with no response-model masking
- Java: `return new ResponseEntity<>(user, OK)` exposing the entity directly; JPA entity with `@JsonIgnore` missing on the sensitive field
- Go: `json.NewEncoder(w).Encode(account)` with a struct field `CardNumber string` lacking `json:"-"` / masking

No masking helper / inline full-digit rendering:
- `console.log('card', user.cardNumber)`, `logger.info(f"auth user={user.email} ssn={user.ssn}")`
- `<td>${user.cardNumber}</td>`, `{{ user.ssn }}`
- `str(user)`, `user.toString()`, `repr(user)` over a model that embeds secrets — common ORM default dumps all fields

Logging raw values / error paths:
- `logger.debug('payload %s', body)` where `body` carries the PAN
- `catch (e) { console.error('failed for', req.body) }` — dumps the inbound secret
- PHP `error_log(print_r($_POST, true))`, Laravel `Log::info('request', $request->all())`
- Ruby `Rails.logger.debug("params=#{params}")`, `logger.error("#{e.message} #{$!.full_message}")`

Missing redaction in serialization config:
- Django/FastAPI response model that includes the sensitive field with no `MaskingField` / `@serde_as` / `Schema` exclude
- Jackson `ObjectMapper.writeValueAsString(entity)` without `@JsonIgnore` / `@JsonSerialize` masking serializer
- Structured logger with no PII scrubber (no redact middleware on `pino`, `zap`, `loguru`, `structlog`)

## False positives
- The field is already tokenized at rest (vault-mapped token stored, PAN never persisted) and only the token is returned — masking is moot.
- A PCI-DSS-compliant tokenization HSM/service is in front, so what reaches the app is a non-reversible token; logging it is fine.
- The display path correctly exposes first-6/last-4 and the full value never leaves a PCI-scoped backend (masking verified end-to-end, not just in the template).
- The "reveal" endpoint requires step-up authentication and authorization, and the full value is delivered only over a mutually authenticated, audited channel — this is legitimate, not leakage.
- The value is a non-sensitive surrogate (system-generated public ID, masked token) that merely looks like a card number (e.g., test `4111...` in a sandbox).

## Attack scenario
1. An attacker with low-privilege access (customer role, or a leaked API token) hits a `GET /api/v1/accounts` list endpoint that serializes the ORM entity directly.
2. The response includes every account's full PAN, SSN, and account number — masking was implemented only in the web UI template, never at the API layer.
3. The attacker scrapes the full dataset in a single request; no logs flag it as a "reveal" because masking was a client concern.
4. Separately, an error path `console.error('validation failed', req.body)` writes the inbound card numbers and passwords into the centralized log store; a support engineer or a second compromise harvests credentials from logs.
5. With raw PANs in hand, the attacker commits card-not-present fraud; with SSNs, identity theft; with API keys in logs, lateral movement to third-party services.

## Impact
- **Confidentiality**: mass exposure of payment data, government IDs, and credentials — directly drives fraud, identity theft, and regulatory breach notifications.
- **Integrity**: leaked secrets/API keys enable unauthorized writes and account takeover in dependent systems.
- **Availability**: a major data-breach disclosure triggers service shutdown, forced password resets, and compliance-driven deprecation of exposed keys.
- Severity scales steeply with volume: a single unmasked list endpoint returning N records becomes an N-record breach in one request. PCI DSS, GDPR, and national-ID statutes impose statutory fines per exposed record.

## Remediation
Mask server-side before serialization; tokenize or encrypt at rest:
```ts
// VULNERABLE — raw PAN returned to client
app.get('/accounts', (req, res) => {
  res.json(accounts.map(a => ({ id: a.id, card: a.cardNumber })));
});

// SAFE — masked at the boundary, raw value never leaves the server
const maskPan = (pan: string) => pan.replace(/\s/g, '').replace(/.(?=.{4})/g, '*');
app.get('/accounts', (req, res) => {
  res.json(accounts.map(a => ({ id: a.id, cardMasked: maskPan(a.cardNumber) })));
});
```
For long-term storage, replace the raw value with a vault token (PAN never persisted by the app) or field-level encryption with the key in a separate KMS/HSM. Run a PII-scrubbing middleware on every logger so any stray `req.body`/`error` log auto-redacts known-sensitive keys — defense in depth against the masking rule being skipped on one code path.

## References
- OWASP ASVS V8.x — Protection of data at rest, in transit, and in use; sensitive data exposure controls
- OWASP WSTG-CRYP-01, WSTG-CRYP-03 — Testing for sensitive data sent over unencrypted channels and weak SSL/TLS
- OWASP Cheat Sheets: User Privacy Protections Implementation, Sensitive Data Exposure
- PCI DSS 3.4 / requirement 12 — Mask PAN on display (first 6 / last 4) and tokenize/encrypt at rest
