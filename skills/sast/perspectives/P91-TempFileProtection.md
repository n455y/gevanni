---
id: P91
name: TempFileProtection
refs: ASVS V12.3.x, V12.4.x / WSTG-CONF-05, WSTG-ATHN-04 / CS: File Upload, Insecure Direct Object Reference Prevention
requires: [backend, file-upload]
---

# P91 — TempFileProtection

## Overview
Temporary files are scratch data written to disk during processing — uploads buffered to `/tmp`, exports rendered before streaming, intermediate parsing artifacts, retry/lock files. The risks are not from the data existing, but from how the path, permissions, and lifecycle are handled. A **predictable name** lets a local attacker pre-create or symlink the path (TOCTOU / symlink race) to overwrite an arbitrary file or read what the app writes next. Default open modes create **world-readable** files that leak sensitive content to any local user. And a **forgotten cleanup** leaves secrets, PII, or parsed input sitting on disk long after the request ends. The root cause is almost always using the OS default temp directory with a guessed filename instead of the language's secure-by-default API (`mkdtemp`, `O_TMPFILE`, `tempfile.mkstemp`).

## What to check
- Are temp paths built from a **fixed or predictable name** (`/tmp/upload.tmp`, `${userId}.json`) rather than a random component?
- Does the open call set an explicit restrictive **mode** (`0o600` / `0600`), or does it fall back to the process umask (often `0644` — world-readable)?
- Is the file created inside a **shared world-writable directory** (`/tmp`, `/var/tmp`, `C:\Windows\Temp`) without a private subdirectory per request?
- Is the file removed on **all exit paths**, including exceptions and process crashes? Look for missing `finally`/`try-with-resources`/context managers.
- Is there a **TOCTOU window** between `exists()`/`access()` check and `open()` that an attacker can win via symlink swap?
- Does the code `open(path, 'r')` a symlink an attacker planted in a shared temp dir to read `/etc/shadow` or a neighbor tenant's file?
- Are uploaded files stored under the web root or served back by a static handler with their original attacker-controlled name?
- Is the temp file written with elevated privileges (root) such that even `0600` exposes it to other root processes (container escape context)?

## Static signals
Fixed/predictable temp paths (multi-language):
- Node: `fs.writeFile('/tmp/work.tmp', ...)`, `fs.writeFileSync(path.join(os.tmpdir(), 'task-' + jobId), ...)`
- Python: `open('/tmp/report.csv', 'w')`, `open(f'/tmp/{user_id}.json')` (vs `tempfile.mkstemp()`/`mkdtemp()`)
- Java: `new File("/tmp/cache.dat")`, `new FileWriter("/tmp/" + id)` (vs `Files.createTempFile()`)
- Go: `os.Create("/tmp/buf")`, `ioutil.TempFile` with an empty prefix and fixed suffix
- PHP: `fopen('/tmp/upload.tmp', 'w')`, `$_FILES[...]['tmp_name']` moved to a guessed name
- Ruby: `File.open('/tmp/sess_' + id, 'w')` (vs `Tempfile.new`)

Missing permissions on open:
- Node `fs.writeFile(p, data)` with no `{ mode: 0o600 }` option
- Python `open(p, 'w')` with no third `mode` arg (default `0666 & ~umask`)
- Java `Files.write(path, bytes)` with no `FileAttribute<?>` set to `rw-------`
- Go `os.WriteFile(p, b, 0644)` or `0o644` (world-readable) instead of `0600`

TOCTOU / symlink-vulnerable patterns:
- `if (fs.existsSync(p)) { ... } fs.writeFileSync(p, ...)` — check-then-use gap
- Python `if not os.path.exists(p): open(p,'w')`
- `fs.open(p, 'r')` of an attacker-controllable path in a shared dir (follows symlinks)
- Java `new FileInputStream(userPath)` in a shared temp dir

Forgotten cleanup:
- `writeFileSync`/`open` with no `try/finally`, no `fs.rmSync`
- Python `open(...)` not in a `with` block; no `os.remove` in `finally`
- Java temp files created without `deleteOnExit()` or try-with-resources (note: `deleteOnExit` does not run on JVM crash)
- Background jobs that create temp files but skip cleanup on error branches

## False positives
- `fs.mkdtemp(os.tmpdir() + '/x-')` creates a **private random-named directory**, and children are written with `mode: 0o600` and removed in `finally` — fully safe.
- Linux `O_TMPFILE` (anonymous inode, no name on disk) — no symlink/TOCTOU surface by construction.
- `tempfile.mkstemp()` / `tempfile.NamedTemporaryFile()` — opens with `0600` and a random name atomically; safe by default unless `dir=` points at a shared dir and the file is later moved unsafely.
- Java `Files.createTempFile(prefix, suffix, PosixFilePermissions.asFileAttribute(Set.of(OWNER_READ, OWNER_WRITE)))` — correct.
- File is written to an app-private directory (`/var/app/tmp`, `data/`) owned only by the service user with `0700` — not the shared OS temp dir, so neighbor attacks do not apply.
- Read-only temp file (e.g., copied **from** a trusted source) where the content is non-sensitive and the name carries no secret.

## Attack scenario
1. The app buffers each user's exported PII to `/tmp/export-${userId}.json` while it streams a download.
2. A local attacker (or co-tenant in a shared host) sees the predictable naming scheme.
3. Before the victim user triggers an export, the attacker runs `ln -s /home/victim/.ssh/authorized_keys /tmp/export-victim.json`.
4. The app opens the path for writing, **following the symlink**, and truncates/overwrites `authorized_keys`, or — flipped — the attacker symlinks it to `/etc/passwd` and reads it via a later `open(path,'r')`.
5. Alternatively: the file is created `0644`, so the attacker simply `cat /tmp/export-victim.json` and harvests every other tenant's exported data.

## Impact
- **Confidentiality**: leaked PII, secrets, session data, or another tenant's records left in a world-readable temp file.
- **Integrity**: arbitrary file overwrite via symlink race (overwrite config, `authorized_keys`, cron job) → code execution as the service user.
- **Availability**: clobbering a critical file can crash the service; filling the temp volume (no size cap) causes disk exhaustion.
- Severity scales sharply with multi-tenancy and shared hosts: a single predictable `/tmp` filename on a shared box can be a full system-compromise primitive.

## Remediation
Use the language's secure temp API, set restrictive permissions, and guarantee cleanup:
```ts
// VULNERABLE — fixed name, default mode, no cleanup
fs.writeFileSync('/tmp/work.tmp', data);

// SAFE — private random dir, 0600, removed on all paths
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'app-'));
const p = path.join(dir, 'work');
try {
  fs.writeFileSync(p, data, { mode: 0o600 });
  work(p);
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
```
```python
# SAFE — atomic random name, 0600, auto-removed
with tempfile.NamedTemporaryFile(prefix='app-', dir=PRIVATE_DIR) as f:
    f.write(data); f.flush()
```
As defense-in-depth, prefer an **app-private scratch directory** (`0700`, service-user owned) over the OS `/tmp`, open files with `O_NOFOLLOW` where available to refuse symlink targets, and add a reaper job that deletes stale temp files older than a short TTL.

## References
- OWASP ASVS V12.3.x — File upload (trusted, randomized names, private storage)
- OWASP ASVS V12.4.x — Files obtained from untrusted sources stored outside the web root
- OWASP WSTG-CONF-05 — File system / temp file exposure
- OWASP Cheat Sheets: File Upload, Insecure Direct Object Reference Prevention
