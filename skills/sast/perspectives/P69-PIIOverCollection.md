---
id: P69
name: PIIOverCollection
area: V14 Data Protection
refs: ASVS V8.2.x, V8.3.x / WSTG-INFO-02, WSTG-ATHN-09 / CS: User Privacy, Privacy Engineering
requires: [backend]
---

# P69 — PII Over-Collection

## Overview
PII over-collection occurs when an application gathers, persists, or logs personally identifiable information beyond what the active feature actually requires — collecting a birthdate, national ID, or biometric for a service that only needs an email. The root cause is rarely a single field: it is the absence of data-minimization discipline (collect-the-least), purpose limitation (use only for the stated purpose), and a retention lifecycle (expire or anonymize). The result is a bloated, high-sensitivity data store with weak deletion guarantees — a prime target for breach exfiltration, insider abuse, and a direct violation of GDPR Art. 5(1)(c)/(e), CPRA, and similar regimes. The more PII you hold without justification, the larger your blast radius and your legal exposure.

## What to check
- Does any registration, profile, KYC, or checkout form collect sensitive attributes (date of birth, full address, national/SSN, passport, biometric, precise geo, financial account) that the feature does not demonstrably need?
- Is there an allow-list / `pick()` on the server side, or is the whole request body persisted verbatim (`User.create(req.body)`, `INSERT ... VALUES (req.body.*)`)?
- Is consent captured **per purpose**, with a record of what the user agreed to, or is there a single "I agree to everything" checkbox covering unrelated processing?
- Is there a working **account deletion / erasure** path (GDPR Art. 17) that performs a hard delete or irreversible anonymization — not a soft-delete flag that leaves PII recoverable?
- Are backups, audit tables, support exports, and analytics warehouses reached by the deletion pipeline, or does "deleted" only mean the row in `users`?
- Is there a **retention schedule**: a job that auto-deletes or anonymizes records after the statutory/contractual window (e.g. 30/90 days, 7 years for tax)?
- Are PII fields written into logs, error reports, APM spans, or analytics events in plaintext?
- Are sensitive attributes stored at rest in plaintext rather than encrypted/tokenized, and is access logged?

## Static signals
Bulk persistence without allow-list:
- Node: `User.create(req.body)`, `db.user.insertMany(req.body.users)`, `await prisma.user.create({ data: req.body })`, `Model.findByIdAndUpdate(id, req.body)`
- Python: `User.objects.create(**request.data)`, `serializer.save()` accepting unrestricted fields, `cursor.execute("INSERT ... %s", [json.dumps(payload)])`
- Java: `userBean.populate(request)` / `BeanUtils.populate(bean, request.getParameterMap())`, JPA `em.persist(entity)` bound to a form with sensitive fields
- Ruby: `User.create(params[:user])` (especially pre-Rails `mass_assignment` / without `strong_parameters`)
- PHP: `User::create($request->all())` (Laravel `$fillable` missing)
- Go: `json.NewDecoder(r.Body).Decode(&user); db.Create(&user)`

Sensitive-field indicators in models/forms (function-unjustified):
- `birthday`, `dob`, `birth_date`, `ssn`, `national_id`, `passport_no`, `gender`, `ethnicity`, `religion`, `biometric`, `fingerprint`, `face_id`, `precise_lat`, `precise_lng`, `geo_accuracy`

Weak / missing deletion and retention:
- `is_deleted = true` / `deleted_at` flag with no hard-delete or anonymize job (soft-delete only)
- Absence of `DELETE`, `anonymize`, `redact`, or `expire` queries / cron / queue handler
- `@Column(updatable = false)` style "immutable PII" with no retention TTL
- `Logger.info("user=" + user)` / `log.info(f"user={user}")` / `logger.debug(req.body)` serializing full entities including PII
- Analytics: `mixpanel.track('signup', req.body)`, `analytics.identify(userId, { email, dob })`, `Segment`/`GA` calls passing raw PII

## False positives
- The field is genuinely required by law or contract and the purpose is disclosed (e.g. DOB for an age-gated product, tax ID for invoicing under retention law). Confirm a documented purpose and that deletion is honored once the obligation lapses.
- PII is tokenized/pseudonymized and the lookup table is separately access-controlled with short retention — the raw value is not sitting in the primary record.
- "Sensitive-looking" fields are non-PII by content (e.g. `dob` = "depth of bedrock" in a domain model) — verify the schema, not just the name.
- Logs scrub PII via a redaction filter / `masked` serializer before write, so raw attributes never hit the sink.

## Attack scenario
1. The app collects `dob`, `address`, and `ssn` at signup for a feature that only needs `email`; it stores them in `users` and never deletes anything.
2. An attacker exploits an unrelated SQL injection (or an insider / backup theft) to dump the `users` table.
3. Because the table holds years of surplus high-sensitivity PII with no retention cutoff, a single breach exposes the full identity-theft payload of the entire user base.
4. Separately, a user submits an erasure request. The app flips `is_deleted=true` but the same PII persists in audit logs, a nightly analytics export, and a 90-day backup — so the "deleted" record is recovered and later leaked. Regulator fines apply for both the breach scope and the failed erasure.

## Impact
- **Confidentiality**: each surplus sensitive field widens breach impact from "an email was leaked" to full identity theft; aggregated PII is high-value on fraud markets.
- **Integrity**: excessive data enables account-takeover enrichment and synthetic-identity fraud.
- **Availability**: not directly affected, but a regulator-mandated processing freeze after a privacy violation can take the service down.
- Severity scales with **field sensitivity** (biometric/SSN > address > email), **volume of records**, and **retention length** — a decade of unnecessary SSNs is a worst-case store.

## Remediation
Minimize at collection, allow-list what you persist, and implement real deletion + retention:
```ts
// VULNERABLE — mass-assign the whole body, never delete, log PII
app.post('/signup', async (req, res) => {
  log.info('signup', req.body);                 // PII into plaintext logs
  const u = await User.create(req.body);         // collects dob/ssn/address silently
  analytics.track('signup', req.body);           // PII into analytics
  res.json(u);
});
app.delete('/me', async (req, res) => { await User.update(req.uid, { is_deleted: true }); });

// SAFE — allow-list, purpose-tag, hard anonymize, scrub logs, TTL
app.post('/signup', async (req, res) => {
  const data = pick(req.body, ['email', 'password_hash']); // collect-the-least
  log.info('signup', { uid: redactEmail(data.email) });    // no raw PII in logs
  const u = await User.create({ ...data, pii_purpose: 'auth', retain_until: ttlDays(90) });
  res.json({ id: u.id });
});
app.delete('/me', async (req, res) => {
  await User.anonymize(req.uid);   // irreversibly null PII across primary + audit + exports
  await Backup.enqueueForget(req.uid);
});
```
Defense-in-depth: encrypt/tokenize sensitive attributes at rest, tag each dataset with a purpose and `retain_until`, run a scheduled job to hard-delete/anonymize expired records, and route all logs through a PII-redaction filter.

## References
- OWASP ASVS V8.2.x, V8.3.x — Data protection, sensitive personal data, retention and disposal
- OWASP WSTG-INFO-02, WSTG-ATHN-09 — Testing for sensitive data and over-privileged credential collection
- OWASP Cheat Sheets: User Privacy, Privacy Engineering
