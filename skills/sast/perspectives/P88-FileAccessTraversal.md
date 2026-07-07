---
id: P88
name: FileAccessTraversal
refs: ASVS V12.1.x, V12.3.x / WSTG-INPV-11, WSTG-ATHZ-01 / CS: Injection Prevention, File Upload
---

# P88 — FileAccessTraversal

## Preconditions

The code resolves user-supplied input to locate resources.


## Overview
Path traversal (directory traversal) occurs when user-controlled input — a filename, path fragment, document ID, or "return URL" — is concatenated into a server-side filesystem path **without normalization and boundary checks**, allowing `../` sequences (or absolute paths, encoded variants, and symlinks) to escape the intended base directory. The flaw is most acute in file-delivery, download, include, export, and thumbnail features that resolve a path from the request rather than from a server-side mapping. The root cause is always the same: the application trusts the path component of user input and resolves it directly against a root with `path.join`/`os.path.join`/string concatenation, never confirming the *resolved* result stays within the trusted root. A successful traversal reads (or, with write semantics, overwrites/deletes) arbitrary files: `/etc/passwd`, source code, secrets, configuration, and sometimes achieves RCE via log poisoning, LFI of uploaded content, or inclusion of attacker-controlled files.

## What to check
- Does any handler build a filesystem path from request data (`req.query`, `req.params`, `req.body`, `req.headers`, a path variable) — download, serve, include, export, attachment, avatar, document, archive, log viewer?
- Is the user value **concatenated** (`path.join(ROOT, x)`, `os.path.join(ROOT, x)`, string `+`, f-string) rather than mapped from a server-side allow-list (UUID → stored path)?
- After joining, is the result **normalized** (`path.resolve`, `fs.realpath`, `os.path.abspath`, `File.getCanonicalPath`) and then **boundary-checked** (`result.startsWith(ROOT + sep)`)? Both steps are required; concatenation alone, or a check on the un-normalized input, is insufficient.
- Are encoded/obfuscated traversal sequences decoded by the framework before the check? `%2e%2e%2f`, `..%252f` (double-encoded), `..%c0%af` (overlong UTF-8), `....//` (naive single-pass filter bypass), UNC `\\..\`, null-byte `%00` (legacy PHP/Java).
- Does the feature accept **absolute paths** (`/etc/passwd`, `C:\windows\win.ini`) directly because `path.join("/root", "/abs")` returns `/abs` in Node/POSIX?
- Are **symbolic links** followed into untrusted territory? Check `fs.readFile`/`open` vs `lstat`; web roots containing attacker-uploaded content plus a symlink is a classic escalation.
- Is a Zip Slip / archive extraction path present? Tar/zip entries named `../../etc/cron.d/x` escape on naive extraction.
- Does the route rely on a permissive static middleware configured with a user-controlled root (`express.static(req.query.dir)`), or on manual `readFile` where `sendFile`/static serving would have been safer?
- For LFI (include/require of a path): does the language `include`/`require`/`import`/`virtual()`/`include_once` a user-influenced path with an attacker-controllable extension or null byte (legacy)?

## Static signals
Path built from request data (vulnerable shape):
- Node: `res.sendFile(path.join(ROOT, req.query.name))`, `res.download(path.join(ROOT, req.params.file))`, `fs.readFile(ROOT + '/' + req.query.f)`, ``fs.readFile(`${ROOT}/${req.body.doc}`)``
- Python: `open(os.path.join(ROOT, name))`, `Path(ROOT) / name`, `send_file(os.path.join(UPLOAD, request.args['f']))`, Django `open(settings.MEDIA_ROOT + f.name)`
- Java: `new File(ROOT, name)`, `Files.readAllBytes(Paths.get(base, part))`, `response.sendFile(f, ...)` (Spring `Resource`/`FileSystemResource`)
- Go: `os.Open(filepath.Join(root, r.URL.Query().Get("f")))`, `http.ServeFile(w, r, filepath.Join(root, name))`
- PHP: `include($_GET['page'])`, `file_get_contents($dir . '/' . $_GET['f'])`, `readfile`, `require`
- Ruby: `File.read(File.join(ROOT, params[:name]))`, `send_file(Rails.root.join('uploads', params[:f]))`

Missing or weak validation (signals to confirm absence):
- No `path.resolve` / `realpath` / `getCanonicalPath` before use
- Check done on the raw input: `if (name.includes('..'))` (bypassed by encoding); `name.replace('../', '')` (single-pass, bypassed by `....//`)
- Boundary check without separator: `startsWith(ROOT)` matches `/var/app-uploads-evil` too; must be `ROOT + sep` or use a normalized prefix
- Null handling: `path.join('/root', '/etc/passwd')` discards `/root` (absolute override)

Archive extraction (Zip Slip):
- Go: `tar.Next()` then `os.Create(filepath.Join(dest, hdr.Name))` without `strings.HasPrefix(clean, dest)`
- Python: `zipfile` loop writing `os.path.join(dest, info.filename)` unvalidated
- Node: `yauzl`/`unzipper` writing `path.join(dest, entry.fileName)`

## False positives
- Path is selected from a **server-side mapping**: the request carries an opaque ID (UUID/integer) that the app maps to a fixed, pre-validated file path; the user never influences the filesystem path string.
- The resolved path is normalized **and** boundary-checked correctly: `real = fs.realpathSync(p); if (!real.startsWith(ROOT + sep)) reject`. Confirm `realpath`/`getCanonicalPath` was used so symlinks are resolved.
- Framework static middleware with a fixed root and symlink-following disabled (e.g. `express.static(ROOT, { dotfiles: 'ignore', fallthrough: true })`) where the user controls only the sub-path and the middleware enforces its own boundary.
- Input is validated against a strict allow-list (known filename set, UUID, `[A-Za-z0-9_-]+\.\w+`) before any path operation.
- The file operation targets a non-filesystem source (database blob, object store key with its own isolation) and the "path" is never interpreted by the OS.

## Attack scenario
1. The app exposes `GET /download?name=report.pdf` that runs `res.sendFile(path.join(ROOT, req.query.name))`.
2. Attacker requests `GET /download?name=../../../../etc/passwd` (or `%2e%2e%2f%2e%2e%2f...` if a naive `..` filter exists).
3. `path.join` collapses the traversal; the resolved path is `/etc/passwd`, outside `ROOT`. Without a normalization + boundary check, the server streams `/etc/passwd` to the client.
4. The attacker escalates: reads application source (`../../app/config/database.yml`), private keys, `.env`, deployment secrets — then pivots to RCE via stolen cloud credentials, an SSH key, or LFI of an uploaded/log-poisoned file.
5. With write semantics (`unlink`, `rename`, archive extraction), traversal becomes arbitrary file overwrite → webshell drop, `.ssh/authorized_keys` append, or `~/.bashrc` poisoning.

## Impact
- **Confidentiality**: full read of any file readable by the service account — credentials, source, configs, keys, logs, DB dumps. Often the highest-impact outcome.
- **Integrity**: if the path feeds a write/delete/extract operation, arbitrary file create/overwrite/delete → webshell, account persistence, config tampering.
- **Availability**: deletion or corruption of application/runtime files can take the service down.
- Severity scales with the service-account privileges and whether the sink is read-only or read/write; traversal into a write sink is typically Critical (RCE).

## Remediation
Map opaque IDs to fixed paths; if a user path is unavoidable, normalize then enforce a strict boundary:
```ts
// VULNERABLE — concatenation only, no boundary check
app.get('/download', (req, res) => {
  res.sendFile(path.join(ROOT, req.query.name)); // ?name=../../etc/passwd escapes
});

// SAFE — normalize (resolves ../, //, and symlink hops) then verify containment
app.get('/download', (req, res) => {
  const real = fs.realpathSync(path.join(ROOT, req.query.name));
  const root = fs.realpathSync(ROOT);
  if (!real.startsWith(root + path.sep)) return res.status(403).end();
  res.sendFile(real);
});
```
Prefer an opaque server-side ID → stored-path lookup over accepting a filename from the client at all; reject absolute paths, null bytes, and unexpected encodings at the input layer; for archive extraction always validate each entry's normalized path against the destination root (Zip Slip). Layer OS-level controls (run the service as a low-privilege user, chroot/container, AppArmor/SELinux, read-only mounts for sensitive dirs) as defense-in-depth so a traversal bug cannot reach `/etc/shadow` or `~/.ssh`.

## References
- ASVS V12.1.x, V12.3.x
- WSTG-INPV-11, WSTG-ATHZ-01
- CS: Injection Prevention, File Upload
