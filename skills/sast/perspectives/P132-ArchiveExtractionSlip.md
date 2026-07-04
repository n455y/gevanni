---
id: P132
name: ArchiveExtractionSlip
area: V5 File Handling
refs: ASVS V5.x / WSTG-INPV-11 / CS: File Upload
---

# P132 — ArchiveExtractionSlip

## Overview
Archive extraction slip (Zip Slip / Tar Slip) occurs when an application extracts an uploaded or fetched archive (zip, tar, rar, 7z, jar) by joining each entry's name directly onto a destination directory **without normalizing or canonicalizing the path first**. Because the attacker controls the archive, they can set an entry name containing traversal sequences (`../`) or absolute paths (`/etc/...`, `C:\Windows\...`). When the target path resolves outside the intended extraction root, the decompressor happily writes the entry's contents wherever the OS allows — overwriting source files, configuration, scheduled-task scripts, or dropping an executable into a startup location. The root cause is the same as any path traversal: trusting attacker-controlled path components and relying on the library instead of an explicit containment check.

## What to check
- Does any code path accept a zip/tar/rar/7z upload (or fetches an archive from a URL) and then extract it server-side? Trace it to the extraction loop.
- For **every** entry, is the destination path constructed by string concatenation (`path.join(dest, entry.name)`, `dest + "/" + name`, `os.path.join(dest, info.name)`) rather than canonicalization + containment check?
- Is there an explicit check that the **resolved** (`realpath`/`Path(...).resolve()`/`File.getCanonicalPath()`) destination starts with the canonical extraction root, after joining? This is the only correct guard.
- Does the code reject or strip entries whose name contains `..`, starts with `/` or a drive letter, or contains a NUL byte / `..\\` on Windows?
- Is the extraction root on the same filesystem as a writable code/config directory (e.g. uploads extracted under `webroot/`, app root, or `/var/www`)? Slip there = RCE via overwrite.
- Are symlinks/hardlinks inside the archive honored on extraction (tar `ISLNK`, zip symlink extensions), allowing escape without `..`?
- Is the decompression bomb risk (decompression ratio / total uncompressed size) also bounded (related but distinct — see denial-of-service angle)?
- Does the chosen library guarantee safe extraction by default (e.g. Ruby `Gem::Package`, Go's archive helpers do NOT — confirm per version; older `unzipper`, `adm-zip`, `extract-zip` <1.7.0, `node-stream-zip`, Python `tarfile`, `zipfile` all require manual guards)?

## Static signals
Concatenation of entry name onto destination without containment check:
- Node: `fs.writeFile(path.join(dest, entry.fileName), ...)`, `adm-zip.extractAllTo(dest, true)`, `unzipper` without `path` validation, `extract-zip` < 1.7.0, `yauzl` + manual join
- Python: `tarfile.extractall(dest)` / `extract()` (CVE-class; use `data.filter='tar'` + member check), `zipfile.ZipFile.extractall(dest)`, `shutil.unpack_archive()`, `os.path.join(dest, member.name)` without `os.path.realpath` prefix check
- Java: `new FileOutputStream(destDir + "/" + zipEntry.getName())`, `Files.copy(in, Paths.get(dest, entry.getName()))`, `ZipFile`/`ZipInputStream` loops without `getCanonicalPath().startsWith()` check
- Go: `filepath.Join(dest, f.Name)`, `os.Create(filepath.Join(dest, hdr.Name))` in `archive/zip` or `archive/tar` loop; `filepath.Clean` alone is NOT sufficient
- PHP: `ZipArchive::extractTo($dest)`, `PharData($x)->extractTo($dest)`, `$zip->getFromName()` joined to path
- Ruby: `Zip::File.open(f) { |z| z.each { |e| File.write(File.join(dest, e.name), e.get_input_stream.read) } }`, `Gem::Package` (safe), raw `archive-zip`
- Rust: `zip::ZipArchive` / `tar::Archive` `unpack()` older versions; manual `dest.join(name)` without canonical prefix check

Suspicious entry-name patterns inside archives (indicators during dynamic testing):
- `../../../../etc/passwd`, `../../../webroot/index.php`, `app/../../../startup.bat`
- Absolute: `/etc/cron.d/x`, `C:\ProgramData\...\Run\evil.exe`
- Symlink entries (tar `typeflag` 1/2) pointing outside root

## False positives
- The library version is provably safe-by-default and was not bypassed: `extract-zip` ≥ 1.7.0, Python's `tarfile` with `filter='data'` (3.12+) and explicit member allow-list, Go's third-party safe extractors that reject non-rooted paths. Still verify the version pin.
- The archive source is fully trusted and integrity-checked (signed internal artifact, not user-uploaded) — lower risk, but flag if the trust boundary is unclear.
- The extraction happens inside a disposable container / ephemeral scratch dir with no access to code or config, and the output is sanitized before promotion (slip is contained by isolation, not by code — acceptable if documented).
- The application only reads archive *contents* into memory (parse, list) without writing to disk — no extraction, no slip.

## Attack scenario
1. Attacker uploads a theme/plugin/translation archive, or triggers a "restore from backup" / "import zip" feature.
2. The archive contains an entry named `../../../../var/www/html/shell.php` (or `../../config/settings.local.json`) whose body is a webshell or a config that injects an API key / disables a check.
3. The handler loops over entries, joins each name onto the extraction root, and writes — the resolved path lands inside the webroot or app config directory.
4. The attacker requests `/shell.php` (RCE) or the app reloads the overwritten config and trusts the attacker's credentials/origins.
5. On Windows targets, an entry like `..\..\..\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\evil.bat` achieves persistence on the next user login; on Linux, overwriting a `.ssh/authorized_keys` or a cron script yields code execution.

## Impact
- **Confidentiality**: arbitrary file read if a later "download extracted file" reflects the slipped path; credential/key theft via overwritten or newly created config.
- **Integrity**: overwrite of application source, templates, dependencies, or config → persistent backdoor, supply-chain-style RCE.
- **Availability**: clobbering critical files crashes the service; combined with a decompression bomb, disk exhaustion.
- Severity typically reaches **Critical** whenever the extraction root is co-located with executable/interpretable code or config the application loads; otherwise High. An admin-only upload endpoint does not downgrade risk if the overwrite path affects a shared runtime.

## Remediation
Canonicalize both the destination root and the joined path, then enforce a strict prefix containment check before writing:
```ts
// VULNERABLE — entry name concatenated without containment
import AdmZip from 'adm-zip';
const zip = new AdmZip(uploaded);
zip.getEntries().forEach((e) =>
  fs.writeFileSync(path.join(destDir, e.entryName), e.getData()) // ../ escapes
);

// SAFE — resolve and verify prefix, reject on escape
import path from 'node:path';
function safeJoin(root: string, untrusted: string): string {
  const rootNorm = path.resolve(root);
  const target = path.resolve(rootNorm, untrusted); // resolves ../ and absolute
  if (target !== rootNorm && !target.startsWith(rootNorm + path.sep)) {
    throw new Error(`Refusing path outside extraction root: ${untrusted}`);
  }
  return target;
}
zip.getEntries().forEach((e) => {
  fs.mkdirSync(path.dirname(safeJoin(destDir, e.entryName)), { recursive: true });
  fs.writeFileSync(safeJoin(destDir, e.entryName), e.getData());
});
```
```python
# VULNERABLE (Python tarfile — historic CVE-2007-4559 pattern)
import tarfile
with tarfile.open(uploaded) as t:
    t.extractall(dest)            # symlink/.. entries escape

# SAFE (Python >= 3.12) — data filter blocks traversal + dangerous types
with tarfile.open(uploaded) as t:
    t.extractall(dest, filter='data')
```
Prefer a library that enforces this by default, extract into a freshly created unique directory, reject symlink/hardlink entries, and run extraction as a low-privilege user inside a container with no write access to code or config — defense-in-depth so a single missed guard does not become RCE.

## References
- OWASP ASVS V5.x — File handling and untrusted file upload/processing requirements
- OWASP WSTG-INPV-11 — Testing for code injection / path traversal during archive extraction (Zip Slip)
- OWASP Cheat Sheet: File Upload — restricting and safely storing/extracting uploaded content
- Snyk "Zip Slip" vulnerability advisory and CVE-2007-4559 (Python tarfile) background
