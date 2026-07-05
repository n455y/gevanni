---
id: P118
name: PrototypePollution
area: V1 Encoding and Sanitization
refs: ASVS V5.x / WSTG-INPV / CS: Prototype Pollution
requires: [backend]
---

# P118 — Prototype Pollution

## Overview
Prototype pollution occurs when attacker-controlled keys — typically `__proto__`, `constructor`, or `prototype` — are blended into an object via recursive merge / clone / extend logic or permissive query-string parsers, so the property is written not onto the target instance but onto `Object.prototype` itself. Every plain object in the same realm then inherits the injected property, which silently changes default values, flips feature flags, or plants a "gadget" property that a downstream library reads and uses unsafely. JavaScript (Node.js and browser) is the canonical target because prototypes are mutable and globally shared, but the class transfers to any language with runtime-mutable base objects. The issue is rarely the end of the chain on its own — its real power is escalation to XSS, authentication/authorization bypass, or RCE via a gadget in a template engine, validation library, or child-process helper.

## What to check
- Does any code recursively merge, clone, deep-extend, or set keys on an object using request-derived data (`req.body`, `req.query`, parsed JSON, query-string) without filtering dangerous keys?
- Are `__proto__`, `constructor`, `prototype` (and case/encoding variants like `__proto__`, `constructor.prototype`, `['__proto__']`) blocked in the merge path? Setting `obj[key] = v` where `key === '__proto__'` without `Object.create(null)` or a deny-list pollutes.
- Is a query-string / form parser invoked with permissive options — `qs` with `allowPrototypes: true`, Express `extended: true` (qs), `body-parser` extended, `fast-querystring`, `querystringify`, custom `URLSearchParams`→object loops — on user input?
- Does `Object.assign`, spread `{...a, ...b}`, lodash `_.merge`/`_.mergeWith`/`_.set`/`_.setWith`, `$.extend(deep, ...)`, `deepmerge`, `extend`, `node-extend`, or a hand-rolled recursive `merge` receive untrusted data? Note: `_.set(obj, '__proto__.x', v)` and dotted path setters are classic sinks.
- Is `JSON.parse` output passed straight into a recursive clone/merge without key validation?
- Are there prototype-pollution gadgets reachable after pollution: template engines (EJS `settings`, Pug, Handlebars helpers), `child_process.spawn/execFile` (env/options merge), `ejs.render`/`pug.compile` options, `minimist`/`yargs`/`lodash` template, cookie/session defaults, `mongoose`/`sequelize` query defaults, boolean feature flags (`isAdmin`, `role`, `verified`) read via `obj.role || 'user'`?
- For path-traversal-style setters (`_.set`, `objectPath.set`, `dottie`), is a dotted `__proto__.polluted` path accepted from user input?
- Is the runtime/library stack patched? Many CVEs are fixed in lodash ≥4.17.20, qs ≥6.10.3, minimist ≥1.2.6, jquery ≥3.5, async ≥2.6.4 / ≥3.2.2, lodash.merge deep variants — confirm pinned versions.

## Static signals
Recursive merge / extend / clone without key filtering:
- `function merge(target, src) { for (const k in src) target[k] = src[k]; }` — shallow, pollutes on `__proto__`
- `if (typeof src[k] === 'object') target[k] = merge(target[k] || {}, src[k]); else target[k] = src[k];` — classic deep-merge sink
- `_.merge(config, req.body)`, `_.mergeWith`, `_.set(obj, req.body.path, req.body.val)`, `_.defaultsDeep`
- `Object.assign({}, req.body)` (shallow — does NOT pollute) vs `deepmerge(req.body, defaults)` (does)
- `Object.fromEntries(Object.entries(req.query))` then merged recursively
- jQuery `$.extend(true, {}, req.body)` — the `true` (deep) flag is the trigger

Query-string / form parsers with prototype-friendly options:
- Express/body-parser `app.use(urlencoded({ extended: true }))` — uses `qs`; safe unless `allowPrototypes: true`
- `qs.parse(str, { allowPrototypes: true })`, `qs.parse(str, { plainObjects: false })`
- Python `urllib.parse.parse_qs` / `Flask request.args.to_dict()` — not prototype-based; skip (Python objects are not `Object.prototype`-shared) unless targeting a JS-engine boundary (Py_mini_racer, V8 bindings).

Path-style setters from user input:
- `lodash.set(obj, req.body.path, value)`
- `objectPath.set(obj, userPath, userVal)`, `dottie.set`, `property-expr`

Gadgets that escalate after pollution:
- EJS: `ejs.render(str, opts)` — `opts.settings['view options']`, `opts.client`, `opts.escape` / `opts.delimiter` → RCE
- Pug: `pug.compile(str, { name, ... })` — code-exec gadget
- Handlebars: `compile` with `allowProtoPropertiesByDefault` / helper injection
- `child_process.spawn(cmd, args, { env, ... })` where options are merged with polluted defaults (NODE_OPTIONS, shell)
- Boolean default reads: `if (user.isAdmin)`, `const role = req.user.role || 'user'` — pollution of `isAdmin`/`role` → auth bypass

## False positives
- The merge uses `Object.create(null)` targets, `Map`/`WeakMap`, or `Object.assign` (shallow) — `Object.assign` does not traverse `__proto__`, so `{...req.body}` and `Object.assign({}, req.body)` are safe.
- The library is a patched version (lodash ≥4.17.20, qs ≥6.10.3, jQuery ≥3.5, minimist ≥1.2.6, async ≥2.6.4) — confirm by `package-lock`/`yarn.lock` pin, not just `package.json`.
- Input is validated by schema (Joi/Zod/ajv) with `additionalProperties: false` and explicit property allow-list before reaching the merge.
- The target language/runtime is not prototype-based (Python, Go, Java static classes) — there is no shared mutable `Object.prototype`; skip unless a JS engine boundary (V8/Node embedded, SSR) is in play.
- Keys are explicitly stripped: a helper deletes `__proto__`/`constructor`/`prototype` before merging, or uses `Object.create(null)` for both source and target.

## Attack scenario
1. The application exposes `POST /api/settings` that runs `_.merge(userConfig, req.body)` (lodash < 4.17.20) or a hand-rolled recursive merge.
2. Attacker sends `{"__proto__": { "isAdmin": true, "role": "admin" }}` (or for qs: `?__proto__[isAdmin]=true`).
3. The merge recurses into `__proto__` and writes `isAdmin: true` onto `Object.prototype`.
4. An authorization check elsewhere reads `req.user.isAdmin` (undefined on the instance) — it now resolves to `true` via the prototype chain, granting admin access.
5. Escalation: the attacker plants a template-engine gadget, e.g. `{"__proto__":{ "settings": { "view options": { "client": true, "escape": "global.process.mainModule.require('child_process').execSync('id').toString" } } }}`, then hits an `ejs.render` endpoint to achieve RCE.

## Impact
- **Confidentiality**: bypass of authz/feature flags exposes data or functions the user should not reach; leaked secrets via gadget-driven RCE.
- **Integrity**: forged identity attributes (`role`, `isAdmin`, `verified`), tampered defaults, arbitrary code execution through a gadget (template engine, child process options).
- **Availability**: pollution of internal flags can disable safety checks, break request handling for all tenants (global prototype), or trigger DoS via an error-gadget; because the prototype is realm-global, a single successful pollution affects every object created afterward, scaling impact to full-process compromise.
- Severity is often High/Critical because pollution alone is low-noise and the gadget determines the ceiling (XSS → auth bypass → RCE).

## Remediation
Block dangerous keys in the merge path and prefer safe libraries/configs:
```js
// VULNERABLE — recursive merge with no key filtering
function merge(target, src) {
  for (const k in src) {
    if (typeof src[k] === 'object') {
      target[k] = target[k] || {};
      merge(target[k], src[k]);
    } else target[k] = src[k];
  }
  return target;
}
merge(config, req.body); // req.body = { "__proto__": { "isAdmin": true } }

// SAFE — deny-list dangerous keys, use null-proto objects
const DANGEROUS = new Set(['__proto__', 'constructor', 'prototype']);
function safeMerge(target, src) {
  for (const k in src) {
    if (DANGEROUS.has(k)) continue;
    if (src[k] !== null && typeof src[k] === 'object' && !Array.isArray(src[k])) {
      target[k] = safeMerge(target[k] || Object.create(null), src[k]);
    } else target[k] = src[k];
  }
  return target;
}
```
Use patched libraries (lodash ≥4.17.20, qs ≥6.10.3 — and never `allowPrototypes: true`), validate request bodies with a schema (`additionalProperties: false`) before merging, avoid `_.set`/path-setters with user-controlled paths, and consider `Object.create(null)` for parsed input and `Object.freeze(Object.prototype)` as defense-in-depth at startup (note: freezes can break third-party libraries, test before shipping).

## References
- OWASP ASVS V5.x — Input validation and injection prevention requirements
- OWASP WSTG-INPV — Testing for Input Validation (prototype pollution variants)
- OWASP Cheat Sheet: Prototype Pollution Prevention
