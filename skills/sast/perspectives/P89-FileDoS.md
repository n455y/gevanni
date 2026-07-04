---
id: P89
name: FileDoS
area: V5 File Handling
refs: ASVS V12.x / WSTG-INPV-11 / CS: File Upload, Denial of Service
---

# P89 — FileDoS

## Overview
File-based denial of service occurs when an endpoint accepts user-supplied files or archives **without bounding their size, count, decompressed footprint, or processing cost**, allowing an attacker to exhaust disk, memory, CPU, or file-descriptor capacity and take the service down. The root cause is trusting the `Content-Length`, the extension, or the apparent byte size: a 10 MB ZIP can decompress to hundreds of GB (a "zip bomb"), a single image can be decoded into gigabytes of pixels, and an unbounded multipart stream can be buffered entirely in RAM. Because uploads are often unauthenticated or cheaply reachable, file DoS is one of the lowest-effort, highest-impact availability attacks against web applications.

## What to check
- Is there a **per-file size limit** enforced server-side (not just client-side `maxFileSize`)? Is the limit applied *before* the whole body is buffered?
- Is there a **per-request total size** limit (sum of all parts) and a **per-user/per-tenant quota** for stored bytes?
- Is there a limit on the **number of files per request** and on the **rate of upload requests**?
- For archives (zip, tar, gz, rar, 7z): is the **decompressed size** and the **compression ratio** capped before extraction? Are nested archives and symlink/path traversal within archives handled?
- For images/media: is the **decoded pixel footprint** (width × height × channels) capped, not just the encoded byte size? Are expensive decoders (e.g. SVG with embedded JS, TIFF, large PNGs) rejected or run in a sandbox?
- Are file bodies **streamed to disk/object storage** or buffered entirely into memory (`req.body`, `Buffer`, `byte[]`, `read()`)?
- Is there a global **request body size limit** at the reverse proxy / framework level (e.g. `client_max_body_size`, `LimitRequestBody`)?
- Does parsing/decoding run with a **timeout** and a memory ceiling so a malicious file cannot hang a worker indefinitely (algorithmic complexity / ReDoS-style attacks on parsers)?

## Static signals
No size/count limits on upload middleware:
- Node/Express: `multer()` / `busboy` / `formidable` / `express-fileupload` configured **without** a `limits` object; `app.use(express.json())` / `express.urlencoded()` without `{ limit: '...' }`
- Python: Flask `request.files['f'].read()` / `save()` with no `MAX_CONTENT_LENGTH`; Django `FILE_UPLOAD_MAX_MEMORY_SIZE` / `DATA_UPLOAD_MAX_MEMORY_SIZE` at defaults or unset
- Java: Spring `MultipartFile` `getBytes()` / `getInputStream()` consumed fully with no `spring.servlet.multipart.max-file-size` / `max-request-size`; Servlet `Part.write()` unbounded
- Go: `r.ParseMultipartForm(32 << 20)` with a small-ish argument but no per-part guard; `io.ReadAll(file)` with no `io.LimitReader`
- PHP: `move_uploaded_file()` with `upload_max_filesize` / `post_max_size` at generous defaults; no app-level cap
- Ruby: Rails `file.read` without `ActiveStorage` size limits

Whole-body buffering into memory:
- `const buf = await readFile(req.files.f)` / `Buffer.concat(chunks)` over an unbounded stream
- `data = request.files['f'].read()` (Flask) / `f.read()` after `open()` of uploaded file
- `byte[] data = file.getBytes()` (Spring)

Archive decompression without ratio/total cap (decompression bombs):
- Node: `unzipper`/`yauzl` extracting without checking `entry.stored` vs `entry.size` or a running decompressed total; `zlib.gunzip(buf)`
- Python: `zipfile.ZipFile(...).extractall()` without checking `infolist()` uncompressed sizes; `tarfile.open().extractall()`
- Java: `ZipInputStream` reading entries with no running-size or count check
- Go: `archive/zip` `zipReader` loop without validating `f.UncompressedSize64`

Unbounded image decode:
- `sharp(buf)` / `jimp` without `limitInputPixels`; Pillow `Image.open(f)` then `.resize()`/`.save()` on attacker-controlled dimensions; `getImageSize` on a 90000×90000 PNG
- SVG accepted and rasterized without restricting embedded `<image>`/`<script>` or external refs

## False positives
- Upload pipeline enforces per-file size, total size, file count, **and** decompressed/ratio limits, streams to object storage, and runs per-tenant quotas — this is the expected secure baseline.
- The endpoint only accepts files after authentication and a paid/invite gate, and a CDN/WAF (Cloudflare, AWS WAF) caps body size upstream — residual risk is the decompressed-footprint path, still worth checking.
- Archives are never expanded server-side (only stored and served verbatim, e.g. virus-scanned and re-streamed) and image dimensions are never decoded — then zip-bomb/pixel-bomb vectors are moot; only raw byte size matters.
- `LimitReader`/`limit` wraps every read and a hard request timeout bounds CPU — confirm the limit is applied to the *decoded* stream, not just the wire bytes.

## Attack scenario
1. Attacker finds an unauthenticated `/api/avatar` upload endpoint with no server-side size limit.
2. They send a 2 GB multipart body in many concurrent connections, each buffered fully in RAM by the framework, exhausting memory and crashing workers (OOM kill).
3. Variant: they upload a 10 MB ZIP whose inner files are themselves highly compressed (compression ratio > 1000:1); an extract-to-disk feature writes 200 GB, filling the volume and taking down every co-located service.
4. Variant: they upload a 1 MB PNG whose dimensions are 50000×50000; the server's thumbnail generator decodes it into ~10 GB of pixel buffer and is killed by the OOM killer or hangs for minutes.
5. The service becomes unavailable to legitimate users for the duration of the attack; recovery may require manual cleanup of half-written temp files.

## Impact
- **Availability**: primary axis — disk exhaustion, OOM kills, worker pool starvation, file-descriptor exhaustion, volume fill cascading to co-tenants. Often trivially repeatable.
- **Integrity**: temp-file pollution, partial writes corrupting shared state, quota bypass letting one tenant consume others' storage.
- **Confidentiality**: usually low, but error paths that echo back file contents or full stack traces can leak metadata; resource contention may also degrade auth/rate-limiting controls.
- Severity scales with reachability (unauthenticated upload = critical), processing depth (archive expansion / image decode = higher), and shared infrastructure (single volume or container memory = blast radius across services).

## Remediation
Enforce layered limits at the edge, the framework, and the application:
```ts
// VULNERABLE — unbounded full read, no limits
import { readFile } from 'node:fs/promises';
app.post('/upload', async (req, res) => {
  const buf = await readFile(req.files.avatar.tempFilePath); // arbitrary size
  await sharp(buf).resize(128, 128).toFile(out);              // decodes attacker dims
});

// SAFE — per-file + total limits, stream, capped decompression, capped decode
import multer from 'multer';
const upload = multer({
  storage: multer.diskStorage({ destination: '/tmp/up' }), // stream to disk, not RAM
  limits: { fileSize: 10 * 1024 * 1024, files: 1, parts: 2, fields: 0 }, // per-part caps
});
app.post('/upload', upload.single('avatar'), async (req, res) => {
  const f = req.file; // multer already rejected oversize at the stream boundary
  await sharp(f.path, { limitInputPixels: 64 * 1000 * 1000 }) // cap decoded pixel count
    .resize(128, 128).toFile(out);
});
```
For archives, iterate entries and reject when the running decompressed total exceeds a cap or when any entry's compression ratio exceeds a threshold (e.g. > 100:1). Add a global `client_max_body_size` / `LimitRequestBody` at the reverse proxy and a hard per-request timeout as defense-in-depth.

## References
- OWASP ASVS V12.x — Files and Resources (file upload, size/quota controls)
- OWASP WSTG-INPV-11 — Testing for File Upload (DoS via upload); WSTG-ATHZ-04 / DoS controls
- OWASP Cheat Sheets: File Upload, Denial of Service, Untrusted Data Boundaries
