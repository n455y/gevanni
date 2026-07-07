---
id: P87
name: UploadPathExecution
refs: ASVS V12.x / WSTG-CONF-04, WSTG-INPV-11 / CS: File Upload, Unrestricted File Upload
---

# P87 — Upload Path Execution

## Preconditions

The code handles file uploads.


## Overview
When uploaded files are stored inside the web root (or any directory the web server interprets or executes), and the file name or extension is attacker-controlled, the upload becomes an arbitrary code execution vector: the attacker uploads a script (`shell.php`, `evil.jsp`, `cmd.aspx`) and simply requests its URL to execute it server-side. Even without code execution, serving attacker-controlled bytes from the application's own origin lets the attacker host phishing pages or mount same-origin XSS. The root cause is storing user content in a location that is both web-accessible and executable, instead of isolating uploads into non-executing storage with random names.

## What to check
- Are uploaded files stored **inside the web root** (`public/`, `static/`, `www/`, `dist/`, `app/static`) or anywhere the server will execute or serve them as scripts?
- Is the stored **filename user-controlled** (`file.name`, `originalname`, `req.body.filename`)? User names preserve dangerous extensions (`.php`, `.phtml`, `.jsp`, `.jspx`, `.asp`, `.aspx`, `.ashx`, `.cgi`, `.pl`, `.py`, `.sh`, `.svg`, `.html`, `.htm`) and enable path traversal.
- Does the upload destination have **script execution enabled**? (Apache `AddType application/x-httpd-php`, IIS handler mappings, Nginx `location ~ \.php$ { fastcgi_pass }`, Tomcat auto-deploying `.jsp`, PHP `engine on` scoped to the dir.)
- Are **double extensions** or legacy null bytes accepted (`shell.php.jpg`, `evil.php%00.png`) to bypass extension filters?
- When serving uploaded content, is `Content-Type` taken from the **user-supplied value** (`file.mimetype`, `req.body.contentType`) rather than re-derived from verified content?
- Is the upload directory the application's runtime / classpath / `webapps`, allowing a `.jsp`/`.war` to be hot-deployed?
- Are uploads served from the **application's origin domain** (same-origin), enabling XSS/phishing from user content?

## Static signals
Web-root storage with user-controlled names:
- Node: `fs.writeFile(\`public/uploads/${file.name}\`, ...)`, `app.use('/uploads', express.static('uploads'))` inside the web root
- Python/Django: writing into a served `MEDIA_ROOT`, `FileField(upload_to='static/')`
- Flask: `request.files['f'].save(os.path.join(app.static_folder, name))`
- PHP: `move_uploaded_file($_FILES['f']['tmp_name'], 'www/uploads/'.$_FILES['f']['name'])`
- Java/Spring: writing under `src/main/webapp/` or `tomcat/webapps/`, `MultipartFile.transferTo(new File("webapp/uploads/"+file.getOriginalFilename()))`
- Ruby/Rails: writing under `public/` (`File.join(Rails.root, 'public', name)`)

User-controlled Content-Type on download:
- `res.set('Content-Type', file.mimetype)` where `file.mimetype` came from the uploader
- `response.setContentType(request.getParameter("type"))`

Execution-enabled upload dirs:
- `.htaccess` allowing execution in the upload dir, IIS handler mapping, PHP `engine on` scoped to uploads
- Tomcat `autoDeploy=true` with uploads under `webapps/`

## False positives
- Uploads are stored **off-origin and outside the web root** (S3/GCS/Azure Blob with no public execution), served via redirect or a dedicated non-executing static domain — protected.
- A **random server-generated name** is used with a fixed safe extension (`crypto.randomUUID() + '.bin'`), stripping user-controlled extensions — protected.
- Content is served with `Content-Disposition: attachment` and a safe `Content-Type` re-derived from magic bytes — protected (still verify same-origin XSS risk).
- The upload is re-encoded/transcoded server-side (images re-saved through a library) so original bytes are never served as-is — protected.
- Files sit in the web root but the server is **serve-only** (no script handlers) and the app re-derives `Content-Type` — protected.

## Attack scenario
1. Attacker finds an image/avatar upload that stores files at `https://app.example.com/uploads/<originalname>`.
2. Attacker uploads `shell.php` containing `<?php system($_GET['c']); ?>` (or `evil.jsp` / `cmd.aspx` matching the stack).
3. The server stores it verbatim at `/uploads/shell.php` inside the web root; the uploads location has PHP/JSP execution enabled.
4. Attacker requests `https://app.example.com/uploads/shell.php?c=id` — the script executes server-side and returns command output: full RCE under the web server's privileges.
5. Failing RCE, the attacker uploads `phish.html` and lures victims to the trusted-origin URL for credential theft, or `steal.svg` for XSS.

## Impact
- **Confidentiality / Integrity / Availability**: server-side Remote Code Execution — total compromise of the host, database, and adjacent services. Typically **Critical**.
- Without code execution: stored XSS from same-origin upload (account takeover), phishing on a trusted domain, malware hosting, disk-exhaustion DoS (see P89).
- Severity scales with the runtime: RCE is Critical; same-origin content hosting (no execution) is High/Medium; off-origin isolated storage reduces it to Low.

## Remediation
Store uploads outside the web root under a random name, never execute them, and serve via a non-executing path or a separate static origin:
```ts
// VULNERABLE — web-root storage, user-controlled name + extension, executable
import fs from 'node:fs';
app.post('/upload', (req, res) => {
  const f = req.files.avatar;
  fs.writeFileSync(`public/uploads/${f.name}`, f.data);   // /uploads/shell.php reachable + executed
  res.json({ url: `/uploads/${f.name}` });
});

// SAFE — off-origin object store, random name, served without execution
import crypto from 'node:crypto';
app.post('/upload', async (req, res) => {
  const f = validateImage(req.files.avatar);              // type + magic bytes + size (see P86)
  const key = `uploads/${crypto.randomUUID()}.bin`;       // random name, no user extension
  await s3.putObject({ Bucket: UPLOADS, Key: key, Body: f.data,
                       ContentType: 'application/octet-stream' });
  res.json({ url: `https://cdn.example.com/${key}` });    // separate static origin, no script handler
});
```
Defense-in-depth: disable script execution in any upload directory at the web server level (`php_admin_flag engine off`, remove handler mappings, an Nginx `location /uploads/` block with no fastcgi), force `Content-Disposition: attachment`, re-derive `Content-Type` from validated content, and serve user content from a separate origin/domain so cookies and same-origin privileges do not apply.

## References
- OWASP ASVS V12.x — Files and resources: upload storage, path, and execution controls
- OWASP WSTG-CONF-04 (server misconfiguration enabling execution), WSTG-INPV-11 (file upload testing)
- OWASP Cheat Sheets: File Upload, Unrestricted File Upload
