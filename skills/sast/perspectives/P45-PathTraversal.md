---
id: P45
name: PathTraversal
refs: ASVS V5.3.7 / V12.3.1, V12.3.2 / WSTG-INPV-11 / CS: File Upload, Injection Prevention
requires: [backend, file-read]
---

# P45 — Path Traversal

## Overview
Path traversal (directory traversal) occurs when user-controlled input — a filename, relative path, document ID, or URL segment — is concatenated into a filesystem path **without canonicalization and containment checks**, letting `../` sequences or absolute paths escape the intended base directory. The root cause is always the same: untrusted data reaches a filesystem API (`fs.readFile`, `open()`, `new File(...)`, `os.Open`) through a code path that joins first and validates later — or never validates at all. `path.join` and Python's `os.path.join` **do not** prevent traversal; they normalize but still honor `../`. Successful exploitation yields arbitrary file read (credentials, source, configs), and in upload/extract flows can reach arbitrary file write or overwrite (webshell drop, key replacement).

## What to check
- Does any handler pass request-derived data (`req.params`, `req.query`, `req.body`, `req.headers`, URL path segment) into a file API — read, write, delete, include, stat, send_file, stream?
- After joining the user value to a base directory, is the result **resolved/canonicalized** (`path.resolve`, `realpath`, `File.getCanonicalPath`, `filepath.Clean`+`Abs`) **and** checked to still start with the base directory prefix?
- Is the prefix check done against the canonicalized path with a trailing separator (`startsWith(base + path.sep)`), not a naive `startsWith(base)` that `/var/www/app-secret` would satisfy when base is `/var/www/app`?
- Are absolute paths (`/etc/passwd`, `C:\windows\win.ini`) and UNC paths (`\\host\share`) blocked? `path.resolve` against an absolute argument discards the base entirely.
- Is the value mapped through an allow-list/ID lookup (e.g. `uuid → on-disk path`) instead of using the raw string?
- For archive extraction (zip/tar), are entry names validated against zip-slip — i.e. resolved target checked to remain under the extraction root?
- For file upload, is the stored filename sanitized (`path.basename`) and is the destination dir fixed, not user-influenced?
- Does a templating/include call (`include($file)`, `require($file)`, `render(file)`) accept request input — often an LFI primitive adjacent to traversal?
- Are NUL bytes (`%00`) stripped? Legacy C-based runtimes and some PHP/Java versions truncate at `\0`, enabling `../../../etc/passwd\0.jpg` bypasses of extension checks.

## Static signals
Join-then-use without containment check:
- Node: `fs.readFile(path.join(BASE, req.query.f))`, `fs.readFile(\`${dir}/${req.params.name}\`)`
- Python: `open(os.path.join(BASE, request.args['f']))`, `Path(BASE) / request.args['f']`, `open(f'{BASE}/{name}')`
- Java: `new File(base, userInput)`, `new FileInputStream(base + "/" + name)`, `Files.readString(Path.of(base, name))`
- Go: `os.ReadFile(filepath.Join(base, r.URL.Query().Get("f")))`, `os.Open(base + "/" + name)`
- PHP: `include($_GET['page'])`, `file_get_contents($dir . '/' . $_GET['f'])`, `fopen($dir.'/'.$_GET['f'])`
- Ruby: `File.read(File.join(BASE, params[:f]))`, `File.read("#{BASE}/#{params[:f]}")`
- C#: `File.ReadAllText(Path.Combine(base, Request.Query["f"]))`

Containment checks to look for as a sign of mitigation (or their absence):
- Node: `if (!p.startsWith(BASE + path.sep))`
- Python: `Path.resolve(...).is_relative_to(BASE)` (3.9+) or `os.path.commonpath`
- Java: `file.getCanonicalPath().startsWith(base.getCanonicalPath() + File.separator)`
- Go: `filepath.Clean(filepath.Join(base, name)); !strings.HasPrefix(cleaned, base+string(os.PathSeparator))`
- C#: `Path.GetFullPath(...).StartsWith(baseDir + Path.DirectorySeparatorChar)`

Other patterns:
- Zip slip: `zipfile.extract(name, dest)` / `tar.extractFile` / `ZipEntry.getName()` joined to dest without validation
- Upload: `fs.writeFile(path.join(uploadDir, req.file.originalname))` — `originalname` may be `../../public/shell.jsp`
- LFI: `include $_GET['page']`, `require_once($module . '.php')` with user-controlled `$module`

## False positives
- The value is an opaque ID (UUID/integer) looked up in a server-side map; the on-disk path is fully server-chosen. Confirm no fallback to raw string usage.
- Canonicalization + `is_relative_to` / `commonpath` / `startsWith(base + sep)` containment is correctly applied before the file API call.
- Static file serving goes through a framework's hardened route (`express.static` rooted at a dir, Nginx `alias`, Django's `STATIC_ROOT`, Rails `send_file` with sanitized path) that rejects traversal by design.
- The base directory is genuinely world-readable scratch space and there is no sensitive sibling to escape to (rare — still verify write paths).
- `path.basename(req.query.f)` is applied before join, stripping all directory components — effective for read, though verify no absolute-path leakage on Windows where `basename("C:\\x")` is `x` but `C:` handling varies.

## Attack scenario
1. App serves user avatars via `GET /file?name=photo.jpg` → `res.sendFile(path.join('/var/app/uploads', req.query.name))`.
2. Attacker requests `/file?name=../../../../etc/passwd`. `path.join` normalizes to `/etc/passwd`; no containment check, so the OS returns it.
3. The attacker enumerates `/proc/self/environ`, application source (`../../../../app/index.js`), SSH keys (`../../../home/deploy/.ssh/id_rsa`), or cloud metadata via SSRF-adjacent reads — escalating to source disclosure and credential theft.
4. In a write/upload variant, an attacker uploads with filename `../../public/assets/shell.php`; the server stores a webshell under the web root and triggers remote code execution.
5. In a zip-slip variant, a malicious archive entry named `../../../etc/cron.d/persist` extracts outside the target dir, achieving persistent code execution as the extraction user.

## Impact
- **Confidentiality**: arbitrary file read — source code, secrets, configs, key material, `/etc/passwd`, environment files. Often the first step to deeper compromise.
- **Integrity**: arbitrary file write/overwrite (upload + traversal) — webshell drop, replacing trusted binaries or keys, tampering with logs or app data.
- **Availability**: deletion or corruption of files (`fs.unlink`, overwrite), DoS via disk fill.
- Severity scales with the I/O mode (read-only vs write), the privileges of the process account, and what sensitive material exists within reach on the host — read of a private key or `AWS creds in env` is effectively full account compromise.

## Remediation
Canonicalize, then verify containment before any filesystem touch; prefer an ID-to-path allow-list over raw user input:
```ts
// VULNERABLE — join only, ../ escapes the base
app.get('/file', (req, res) => {
  res.sendFile(path.join('/var/app/uploads', req.query.name));
});

// SAFE — resolve to canonical absolute path, enforce containment
app.get('/file', (req, res) => {
  const base = path.resolve('/var/app/uploads');
  const target = path.resolve(base, req.query.name);
  if (target !== base && !target.startsWith(base + path.sep)) {
    return res.status(403).send('Forbidden');
  }
  res.sendFile(target);
});
```
For extraction, validate every entry: `path.resolve(dest, entry.fileName)` must remain under `dest + sep`; reject otherwise. Defense-in-depth: run the app/worker under a least-privilege account, chroot or container-mount the base directory read-only where reads suffice, and apply a filename allow-list (UUID-stored names) for uploads.

## References
- OWASP ASVS V5.3.7 — Verify path-traversal protection (input validation), V12.3.1/V12.3.2 — file upload path and metadata handling
- OWASP WSTG-INPV-11 — Testing for Path Traversal
- OWASP Cheat Sheets: File Upload, Injection Prevention
- MITRE CWE-22 (Path Traversal), CWE-23/CWE-36/CWE-40 (relative/absolute/root traversal), CWE-22 via zip-slip (CWE-22)
