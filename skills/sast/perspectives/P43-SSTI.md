---
id: P43
name: SSTI
area: V1 Encoding and Sanitization
refs: ASVS V5.3.x / WSTG-INPV-13 / CS: Injection Prevention, Server Side Template Injection
---

# P43 — SSTI

## Overview
Server-Side Template Injection (SSTI) occurs when user-controlled input is treated as a **template source** (compiled and evaluated by the templating engine) rather than as a passive **data value** passed into a fixed template. The payload — typically `{{ ... }}`, `${ ... }`, or `<%= ... %>` depending on the engine — is executed on the server inside the engine's expression/sandbox context, which usually exposes the host language's runtime (Python `__class__`, JS `process`, Java reflection, Ruby `system`). Root cause is always the same: the boundary between "template string" and "template argument" is blurred — `render(userString)` instead of `render(templateFile, { data: userString })`. Because the engine runs with full application privileges, a successful SSTI almost always escalates to Remote Code Execution, file read, or full server compromise.

## What to check
- Does any handler pass request-derived data (`req.query`, `req.body`, `req.params`, `request.POST`, `$_GET`, request headers) as the **first** argument to a render/compile call (the *template source*) rather than as a member of the *data/context* argument?
- Are templates constructed by string concatenation or interpolation that includes user input (`"Hello " + name` fed to `compile`, or `f"...{user}..."` fed to `render_template_string`)?
- Is the template engine's expression/sandbox reachable from user input? Look for `{{7*7}}` → `49` style probes in logs, orin code paths that render mail bodies, PDF/HTML reports, CMS pages, or admin "test render" features.
- Does the app use a logic-full engine (Jinja2, Twig, FreeMarker, Velocity, EJS, Pug, Nunjucks, T4, Smarty, Mako) — these are high-risk. Logic-less engines (Mustache/Handlebars without helpers) are lower risk but not immune if helpers/`compile(userInput)` are used.
- Are there custom "formula", "merge-field", or "mail-merge" features that compile user-supplied expressions? These are functionally SSTI even if not branded as templates.
- Does the engine expose a dangerous global (Express `process`, Django settings object, Spring `applicationContext`, FreeMarker `freemarker.template.utility.Execute`) reachable from a template expression?
- Is the template string built from multiple sources (DB-stored partial + query param) such that the query param can inject `{{ }}` into the rendered string?

## Static signals
Treating input as template source (vulnerable patterns):
- Node: `ejs.render(req.body.tpl)`, `ejs.renderFile` with a user-controlled path, `nunjucks.renderString(userInput)`, `pug.render(userInput)`, `Handlebars.compile(userInput)`, `mustache.render(userInput, data)` (when `userInput` is the template)
- Python: `render_template_string(user_input)`, `Template(user_input).render()`, `Mako Template(user_input)`, `tornado.template.Template(user_input)`, `string.Template(user_input).substitute(...)`
- Java: `new TemplateEngine().process(userInput, ctx)` (Thymeleaf), `freemarker.core.Environment`/`Template(userInput...)`, `VelocityEngine.evaluate(ctx, w, "x", userInput)`, `pebble.evaluate(...)`, `Jinjava` `render(userInput, ...)`
- PHP: `$twig->createTemplate($_GET['tpl'])->render(...)`, `Smarty::fetch('string:'.$_GET['tpl'])`, `sprintf`-built string passed to `eval`-like template
- Ruby: `ERB.new(user_input).result`, `Slim::Template.new { user_input }.render`, `Liquid::Template.parse(user_input)` (Liquid is sandboxed by design — verify custom drops/tags)
- Go: `text/template` `Execute` on a template whose source string includes user input
- Generic / multi-lang: `eval`/`Function`/`exec` over a string built from user input (SSTI's cousin — code injection)

Escaping-disabled or logic-injection signals:
- Template source assembled with concatenation: `"{{ greeting " + name + " }}"`, `f"<p>{user_text}</p>"` then `render_template_string(...)`
- DB-stored "template" columns rendered without sandboxing: `render_template_string(Page.objects.get(slug=slug).body)`
- Mail/notification rendering of admin-edited templates with full engine context

## False positives
- Input is passed as a **data/context value** to a fixed, file-based template: `res.render('view.ejs', { msg: req.body.msg })`, `render_template('view.html', {'msg': msg})`, `twig->render('view.twig', ['msg' => $msg])`. Auto-escaping applies and the input never reaches the compiler as source.
- Logic-less engine with no helpers and no `compile(userInput)`: pure Mustache `{{name}}` only expands keys from a provided data object; the engine does not evaluate user-supplied template text. Confirm `Mustache.render()`'s *first* argument is a server-controlled file/string.
- The input is a strict allow-list of pre-approved templates selected by an enum/ID (`template_id in ('welcome','reset')`), not free text.
- A genuinely sandboxed engine with a hardened, escape-proof sandbox is used (rare — verify the sandbox has no known bypasses for the engine version; e.g., FreeMarker `?api`, Jinja `__class__`, Thymeleaf expression-object reachability are common escapes).
- The "template" is rendered client-side only (browser templating) — that is XSS, not SSTI; cross-check with P38/P40.

## Attack scenario
1. Attacker submits a probe in any field that is reflected into a render call: `{{7*7}}`. If the response contains `49` (not `{{7*7}}`), SSTI is confirmed.
2. Attacker fingerprints the engine with a polyglot payload: `${7*7}` (FreeMarker/Velocity/EJS), `{{7*7}}` (Jinja/Twig/Nunjucks), `<%= 7*7 %>` (EJS/ERB), `#{7*7}` (Thymeleaf). The reflected form reveals the engine.
3. Attacker escalates to RCE via an engine-specific gadget:
   - Jinja2: `{{ cycler.__init__.__globals__.os.popen('id').read() }}` or `{{ self.__class__.__mro__[1].__subclasses__() }}` traversal.
   - FreeMarker: `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` (pre-2.3.30) or `?api` bypass.
   - Velocity: `#set($x=$Runtime.getRuntime().exec("id"))`.
   - Twig: `{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}` (older versions).
   - EJS/Node: `<%= process.mainModule.require('child_process').execSync('id') %>`.
   - Thymeleaf: expression-object / OGNL-style injection via fragment expressions (`__${...}__`).
4. Attacker reads secrets (`/etc/passwd`, env vars, app config), establishes a reverse shell, or pivots to internal services — the process has the full privileges of the web server.

## Impact
- **Confidentiality**: full read of source code, secrets, env vars, DB credentials, and any file readable by the service account.
- **Integrity**: arbitrary code execution → data tampering, backdoor installation, persistence, fraudulent transactions.
- **Availability**: process kill, disk wipe, ransomware-style encryption, resource exhaustion — server is fully owned.
- Severity is routinely **Critical (CVSS 9.8)** when a full-expression engine is reachable; even a sandboxed engine may rate High if the sandbox has bypasses. Scale by privilege: a root/container-privileged server equals total host/container compromise.

## Remediation
Never let user input be the template source — pass it as data to a server-controlled template:
```ts
// VULNERABLE — input is the template source
const html = ejs.render(req.body.template);

// SAFE — input is data inside a fixed server-side template
const tpl = fs.readFileSync(path.join(viewsDir, 'greeting.ejs'), 'utf8');
const html = ejs.render(tpl, { msg: req.body.msg }); // msg is HTML-escaped by <%= %>
```
```python
# VULNERABLE
return render_template_string(f"Hello {name}")   # name can inject {{ }}

# SAFE
return render_template("greeting.html", name=name)  # fixed template, name is auto-escaped data
```
For unavoidable dynamic templates (CMS, report builders), enforce a sandboxed, logic-restricted engine (Liquid, a curated Mustache subset), reject input containing expression delimiters (`{{`, `${`, `<%`, `#{`) via allow-list validation, render in a least-privilege process/container with no secrets in the environment, and run the engine at the lowest possible privilege. Defense-in-depth: keep the engine patched (sandbox-bypass CVEs are frequent) and never expose dangerous globals (`process`, `os`, `applicationContext`, settings objects) to the template context.

## References
- OWASP ASVS V5.3.x — Output encoding and injection prevention (template injection as injection class)
- OWASP WSTG-INPV-13 — Testing for Server-Side Template Injection
- OWASP Cheat Sheets: Injection Prevention, Server Side Template Injection
