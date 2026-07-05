---
name: sast
description: Use when the user wants a white-box (source-code) security review of web application code — asking to find vulnerabilities, audit routes/handlers/controllers for security issues, or check code against OWASP ASVS/WSTG/CheatSheet. Trigger phrases include "run a security assessment", "check for vulnerabilities", "source code security review", "ASVS-compliant assessment", "audit endpoints for injection/auth/authz/crypto issues", "find vulnerabilities in this code".
---

# SAST

## Overview

White-box static analysis (SAST-style). Split the target web application's **source code** by routing/handler units, then fan out sub-agents across the cartesian product of **perspectives (133) × units** for assessment. The execution engine is Dynamic Workflow. No dynamic testing (sending real requests) is performed — dynamic assessment is complemented by the `gevanni` scanner.

**Core principle**: 1 sub-agent = 1 assessment unit × 1 perspective. Keep the context small to increase detection precision and reduce false positives.

## Prerequisites & Ethics

- **Authorized targets only**. Step 0 confirms the target and authorization (in-house code / CTF / commissioned penetration testing / learning samples, etc.). If unclear, confirm with the user before executing.
- **Static analysis only**. No requests are sent to external services, and no live environments are scanned.
- Findings represent "possibility". Areas where framework protections (parameterized queries, automatic escaping, typed inputs, etc.) are effective are basically out of scope. FPs are explicitly indicated by confidence level.

## Workflow

### Step 0: Confirm target & authorization

- Identify the directory/repository to be assessed.
- Confirm the authorization scope. If unclear, check with the user before proceeding.

### Step 1: Source analysis and unit splitting

Extract routing/handlers to create **assessment units**.

Framework-specific routing detection patterns:

- **Express/Connect/Koa**: `app.get/post/put/delete/patch`, `router.METHOD`, `app.use`
- **Fastify**: `fastify.get/post`, `fastify.route`
- **Hono**: `app.get/post`, `router.use`
- **Next.js**: `pages/api/**`, `app/api/**/route.ts` (GET/POST exports)
- **NestJS**: `@Get/@Post/@Put/@Delete/@Patch` in `@Controller`
- **Spring (Java/Kotlin)**: `@GetMapping/@PostMapping/@RequestMapping/@RestController`
- **Django/Flask/FastAPI**: `@app.route`, `@router.get/post`, `def get_*`, function-based views
- **Go**: `http.HandleFunc`, Gin/Echo/Chi's `router.GET/POST`, `r.Get`

Each unit should include:

- HTTP method + path
- Handler body
- Service / validator / DAO / models called by the handler (within reachable scope)
- `tags`: `string[]` — Code capability tags. Used to skip clearly impossible perspective combinations. The filter is **conservative**: a perspective is skipped **only when the unit demonstrably lacks a capability that is physically required** for the vulnerability to exist.
  - **Environment** (include one):
    - `"frontend"`: Client-side only (React/Vue components, static JS/TS, browser APIs, DOM manipulation)
    - `"backend"`: Server-side (API handlers, controllers, services, SSR pages, middleware)
  - **Hard capability gates** (add when present — these are the only tags used for filtering):
    - `"db"`: Database access (SQL or NoSQL) → SQLi, NoSQLi, StoredXSS
    - `"subprocess"`: OS command / subprocess execution → Command Injection
    - `"ldap"`: LDAP queries → LDAP Injection
    - `"xml"`: XML parsing (`xml2js`, `lxml`, `javax.xml`, `jackson-dataformat-xml`) → XXE
    - `"templating"`: Server-side template engine (EJS, Pug, Jinja2, etc.) → SSTI
    - `"deserialization"`: Dangerous deserializers (`pickle`, `unserialize`, `ObjectInputStream`) → Insecure Deserialization
    - `"file-read"`: File system reads (`fs.readFile`, `send_file`, etc.) → Path Traversal, LFI
    - `"redirect"`: HTTP redirect (`res.redirect`, `Location` header) → Open Redirect
    - `"jwt"`: JWT handling (`jsonwebtoken`, `jose`, `java-jwt`) → JWT Validation, Self-contained Tokens
    - `"graphql"`: GraphQL endpoint → GraphQL-specific
    - `"websocket"`: WebSocket handling → WebSocket-specific
    - `"file-upload"`: File upload handling → Upload-specific
    - `"csv"`: CSV export → CSV Formula Injection
    - `"email"`: Email sending → Email Header Injection
    - `"webrtc"`: WebRTC → WebRTC
  - **Why only these?** Perspectives like OAuth, Crypto, Auth/Session, CSRF, Rate Limiting, SSRF etc. are intentionally NOT gated by tags — they can arise through library usage, framework features, or adjacent code, even when the capability isn't explicitly visible. They fall back to environment-based filtering (backend/frontend) only.
  - If uncertain whether a tag applies, **omit it**. Missing tags only cause false negatives (skipped perspectives), never false positives.

**Splitting strategy (scale control)** — this is the key to cost:

- 1 unit = 1 endpoint as a baseline.
- Number of agents = `number of units × number of perspectives (133)`. If the number of units bloats (>8), bundle them by resource/module. Target **N ≤ 5–8**.

Output: `units: Array<{ id, method, route, code, deps, tags }>`. `id` is `U01`, `U02`...

### Step 2: Load perspective catalog + pre-filter

- Under `perspectives/`, there is **one file per perspective** (`P<seq>-<english-name>.md`, e.g. `P38-ReflectedXSS.md`). First read the overall index in `perspectives/README.md`, and skip perspective files for areas clearly absent from the target code (e.g. no GraphQL → skip V4 GraphQL perspectives; no file upload → skip V5 upload perspectives) for token efficiency. **Skipped areas must be explicitly listed in the report's "Out of scope" section (No-silent-caps)**.
- From each file read, assemble `{ id, name, requires, focus, signals, fpNote, refs }`. Each file follows a frontmatter (`id`/`name`/`refs`/`requires`) + body (`## What to check` / `## Static signals` / `## False positives`) structure (see README for details).
  - `requires` is a string array in the frontmatter (e.g. `requires: [backend, db]`). Empty array `[]` means the perspective runs on **all** units. Each perspective file self-declares its requirements — there is no separate mapping in the workflow script.
- **Pre-filter**: For each unit, exclude obviously irrelevant perspectives. The workflow template matches `unit.tags` against `pov.requires`:
  - Unit must have **all** tags listed in `requires`. Missing any → **skip**.
  - `requires: []` → always runs.
  - Unit `tags: ["frontend"]` + `requires: ["backend", "db"]` → **skip**（例: フロントエンドコードにSQLiは不要）
  - Unit `tags: ["backend"]` (no `ldap` tag) + P37 `requires: ["backend", "ldap"]` → **skip**（例: LDAPを使わないシステムにLDAP Injectionは不要）
- Order perspectives by **priority** (Critical-leaning / high-frequency first) — this ensures the safety valve (the cap in `workflow-template.js`) that prunes by priority on scale overflow works correctly.

Output: `perspectives: Array<{ id, name, requires, focus, signals, fpNote, refs }>`.

### Step 3: Fan-out assessment via Dynamic Workflow

Pass `workflow-template.js` to Workflow via `scriptPath`, and inject the results of Steps 1 & 2 into `args`:

```
Workflow({
  scriptPath: "<absolute-path>/.claude/skills/sast/workflow-template.js",
  args: { units, perspectives }
})
```

The script runs `pipeline(units, parallel-assess each unit across all perspectives, merge)` and returns structured FINDINGS. Concurrency is 16, budget is applied automatically, and a 1000-agent safety cap is built in. The return value is `{ summary, units, findings }`.

### Step 4: Generate integrated report

Feed the Workflow's return value into `report-template.md`, generate a single Markdown report, and save & present it.

## Output contract

The report has 4 blocks (see `report-template.md` for details):

1. **Executive summary**: Scope, counts by severity, key findings, limitations
2. **Risk list**: Quick-reference table of all findings sorted by severity → confidence
3. **Perspective-specific details**: Location / confidence / references / evidence / remediation
4. **Notes**: Note that this is static analysis, FP handling, out-of-scope perspectives

Each finding has:

- `povId` (perspective ID) / `severity` (Critical/High/Medium/Low/Info) / `confidence` (high/medium/low) / `title` / `location` (file:line or METHOD path) / `evidence` (code snippet + reason) / `remediation` / `refs` (ASVS/WSTG/CS)

## Common Mistakes

| Common pitfall                                         | Correct approach                                                                                          |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| Running dynamic tests                                  | This skill is static-only. Dynamic testing goes to `gevanni`                                              |
| Applying all perspectives to all units unconditionally | Drop via 2-layer filter: hard capability gates (SQLi→needs DB, GraphQL→needs GraphQL) + environment (frontend/backend). Most perspectives (OAuth, Crypto, XXE, etc.) are intentionally NOT gated — they run on all matching units. |
| Setting unit `tags` incorrectly | Be conservative: if unsure whether a tag applies, omit it. Missing tags only cause skipped perspectives, not missed vulnerabilities. Each perspective's `requires` is defined in its own file — there is no separate mapping to maintain. |
| Splitting units too finely (50+)                       | Bundle by resource to keep N≤5–8. Agent count = N × perspectives                                          |
| Ignoring framework protections and mass-producing FPs  | Parameterized queries / automatic escaping / typed inputs are considered protections and are out of scope |
| Silently dropping skipped perspectives                 | Explicitly list them in the report's "Out of scope" section (No-silent-caps)                              |
| Stuffing multiple perspectives into one agent          | 1 agent = 1 perspective. This is the core of precision and FP reduction                                   |
| Reading all perspective files at once                  | Skip chapters for areas absent from the target (token efficiency)                                         |
