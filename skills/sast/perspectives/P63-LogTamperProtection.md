---
id: P63
name: LogTamperProtection
area: V16 Security Logging and Error Handling
refs: ASVS V7.1.x / WSTG-ATHZ-06, WSTG-ATHN-01 / CS: Logging
requires: []
---

# P63 — Log Tamper Protection

## Overview
Audit and security logs are the primary forensic record after a breach — they establish *who* did *what* and *when*. Log tamper protection addresses the threat that an attacker (or a compromised application account) can rewrite, truncate, or delete those records to cover their tracks, defeating detection, incident response, and compliance controls (PCI DSS, SOX, HIPAA, ISO 27001). The root cause is almost always operational: logs are stored on the **same host and under the same (or higher) privileges** as the application, written via overwrite-capable APIs, or never replicated off the host. Per ASVS V7.1.x, logs must be written to a destination the application cannot rewrite — append-only files under a separate low-privilege account, a remote SIEM/log management service streamed over a one-way or network-restricted channel, or WORM/object-locked storage. If the application process can edit its own audit trail, integrity is lost.

## What to check
- Are security-relevant events (authn successes/failures, access-control decisions, privileged actions, config changes, data exports) actually written to a **separate audit log**, not just console/stdout?
- Is the log sink **append-only** (file mode `O_APPEND` / `'a'`, `>>` redirect, `a` fopen flag) rather than overwrite-capable (`fs.writeFile`, `open('w')`, `truncate`)?
- Are logs persisted with **different privileges** than the application? The app user should not own or hold write/delete rights on the log directory.
- Is there a **remote/external transfer** to a system the compromised host cannot reach for writes — SIEM, object storage with Object Lock/WORM, syslog relay on an isolated network segment?
- Are logs stored in a database table that the same DB user/role can `UPDATE`/`DELETE`/`DROP`? Tamper-evident hashing or an insert-only (append) privilege must constrain this.
- Is log **rotation, retention, and access control** configured? Missing rotation causes DoS via disk exhaustion; missing retention/ACLs let attackers age out or read sensitive entries.
- Are log entries **chain-hashed or signed** (each entry includes a hash of the prior entry, or an HMAC) so silent tampering is detectable?
- Does the log path come from a **user- or config-controllable value** (path traversal leading to overwriting arbitrary files)?
- Does the application hold the **write key/credential** needed to mutate logs in the same process that can be compromised?

## Static signals
Overwrite-capable writes to local log files:
- Node: `fs.writeFile('audit.log', ...)`, `fs.writeFileSync(...)`, `fs.truncate(...)`, `fs.open(path, 'w')`, `fs.open(path, 'r+')`
- Python: `open('audit.log', 'w')`, `open(..., 'r+')`, `file.truncate()`, `logging.FileHandler` with mode `'w'` (default is `'a'` — verify)
- Go: `os.Create(...)`, `os.WriteFile(...)`, `os.OpenFile(..., os.O_TRUNC|os.O_WRONLY, ...)`
- Java: `new FileOutputStream("audit.log")` or `new FileWriter(...)` (both truncate by default — contrast `append=true`)
- PHP: `file_put_contents('audit.log', $x)` without `FILE_APPEND`, `fopen(..., 'w')`
- Ruby: `File.open('audit.log', 'w')`, `File.write(...)`

Append-capable, but verify privilege/transfer:
- Node: `fs.createWriteStream(path, { flags: 'a' })`, `fs.appendFile(...)`
- Python: `logging.FileHandler(..., mode='a')`, `open(..., 'a')`
- Go: `os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)`
- Java: `new FileWriter(path, /*append*/ true)`, Logback `RollingFileAppender`
- Shell: `>>` (append) vs `>` (truncate)

Tamper-prone database sinks:
- ORM/SQL writes to an audit table via the **same connection/role** used for business data — no insert-only constraint, no hash column, row updatable by the app role:
  - `INSERT INTO audit_log (...)` is fine only if the role lacks `UPDATE`/`DELETE` on that table.
- `UPDATE audit_log SET ...`, `DELETE FROM audit_log`, `TRUNCATE audit_log` — direct mutation paths.

Path/location from untrusted or config source:
- `logger.addTransport(new File({ filename: req.body.logPath }))`
- `logging.FileHandler(os.getenv('AUDIT_PATH'))` where the env var is attacker-influenced.

Missing off-host shipping:
- No transport to syslog/SIEM/S3/BigQuery; only a local file or local DB row.

## False positives
- Append-only flag **plus** a separate low-privilege owner **plus** off-host streaming (syslog/SIEM, S3 with Object Lock, GCP Bucket Locked retention) — protected.
- The application can only **write/append** and cannot read back or reopen truncate (write-only channel, e.g., firehose to SIEM) — protected.
- Logs are emitted to **structured stdout/stderr** consumed by an immutable platform sink (Kubernetes node logs shipped by Fluentd, AWS CloudWatch with log-group protection, systemd-journal `journalctl --vacuum` restricted to root) where the app container has no path access.
- An explicit tamper-evident design: chain-hashed (each record stores `H(prev || record)`) or signed entries written to an insert-only table the app role cannot update — protected even without off-host copy.
- `mode='a'` is the **default** for `logging.FileHandler` and `winston`/`pino` file transports — do not flag merely because append is not spelled out; confirm no truncate and no shared privileges.

## Attack scenario
1. An attacker obtains remote code execution or a privileged application account (e.g., via SQL injection, deserialization, or stolen admin creds).
2. They enumerate the logging configuration and find the audit log is a local file written by the same process (`/var/log/app/audit.log`, owner = app user, mode `rw-r--r--`).
3. To hide evidence of credential exfiltration, they truncate or rewrite it: `fs.writeFileSync('/var/log/app/audit.log', cleanEntries)`, `> audit.log`, or `DELETE FROM audit_log WHERE event='export'`.
4. Because no copy was shipped off-host and the chain is not hashed, the tampering is undetectable. Incident responders reconstructing the breach find no record of the malicious actions.
5. Alternatively, the attacker **floods** the log (injecting millions of fake entries via a log-injection vector) to push real entries past retention and age them out, or to exhaust disk and crash the service (DoS).

## Impact
- **Integrity**: the forensic record is unreliable — attackers erase evidence of intrusion, fraud, or privilege abuse. Compliance (PCI DSS req. 10, SOX) audit failures.
- **Confidentiality**: logs often contain PII, tokens, or secrets; if the app can read them, so can the attacker.
- **Availability**: unbounded local logging enables disk-exhaustion DoS; loss of logs disables monitoring/alerting that would have detected the attack in progress.
- Severity scales sharply: tamper-prone logs on a system handling regulated data (financial, healthcare) turn a containable incident into a reportable breach with no forensic trail.

## Remediation
Write append-only under separate privileges and stream off-host; never let the application truncate or rewrite its audit trail:
```ts
// VULNERABLE — overwrite-capable, same-privilege local file, no off-host copy
import fs from 'node:fs';
fs.writeFileSync('audit.log', JSON.stringify(event));            // truncates each call
fs.writeFile(`/var/log/app/${req.body.name}.log`, event);       // path-controlled

// SAFE — append stream, separate owner, ship to SIEM/locked object store
import fs from 'node:fs';
const audit = fs.createWriteStream('/var/log/app/audit.log', { flags: 'a', mode: 0o640 });
audit.write(JSON.stringify(event) + '\n');                        // append-only
siemTransport.send(event);                                       // off-host, app can't reach for writes
```
```python
# Python — append, separate privilege, chain-hashed
import logging
h = logging.FileHandler('/var/log/app/audit.log', mode='a')      # never 'w'
h.setFormatter(logging.Formatter('%(message)s'))
# ownership: chown syslog:adm audit.log; app user has no write/delete
# each record: payload + HMAC(prev_hash || payload) for tamper evidence
```
Defense-in-depth: combine append-only + separate privilege + off-host replication + chain-hashing/HMAC so that even a full host compromise cannot silently alter the trail; rotate logs to size/time caps with restricted retention deletes to prevent both disk-exhaustion DoS and retention-based evidence aging.

## References
- OWASP ASVS V7.1.x — Log content, protection, and tamper resistance
- OWASP WSTG-ATHZ-06 — Testing for log tampering / WSTG-ATHN-01 — Testing for logging and monitoring
- OWASP Cheat Sheet: Logging
