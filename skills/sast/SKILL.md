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

- `id`: `"U01"`, `"U02"`, ...
- `method` + `route`: the HTTP method and path pattern
- `desc`: short description of what this unit does (1-2 sentences)
- `files`: list of source files (relative to repo root) that contain the handler code. Agents will read these to assess relevance.
- `deps`: other source files called by the handler (for context)

No tags needed. Pre-filtering is not done by the workflow — each agent reads the actual code and determines for itself whether its perspective applies.

**Splitting strategy (scale control)** — this is the key to cost:

- 1 unit = 1 endpoint. **Never bundle endpoints together.** Each endpoint has a different attack surface. Bundling reduces precision.
- If the agent count exceeds the limit (1000), `workflow-template.js` splits perspectives into batches and executes them sequentially. Nothing is silently dropped.

Output: `units: Array<{ id, method, route, desc, files, deps? }>`. `id` is `U01`, `U02`...

### Step 2: Load perspective catalog + pre-filter

- Under `perspectives/`, there is **one file per perspective** (`P<seq>-<english-name>.md`). First read the overall index in `perspectives/README.md`, and skip perspective files for areas clearly absent from the target code (e.g. no GraphQL → skip V4 GraphQL; no file upload → skip V5 upload; no OAuth → skip V10). **Skipped areas must be explicitly listed in the report's "Out of scope" section (No-silent-caps)**.
- From each file read, assemble `{ id, name, precondition, focus, signals, fpNote, refs }`. Each file follows a frontmatter (`id`/`name`/`refs`) + body (`## Preconditions` / `## What to check` / `## Static signals` / `## False positives`).
  - `precondition` is the absolute minimum requirement (1 sentence). If the code doesn't satisfy it, the perspective is skipped **by the agent at runtime** (returns `findings: []`).
  - Per-unit tag filtering is **not used**. The workflow runs every perspective against every unit; agents self-determine relevance by reading the actual code and checking `precondition`.
- Order perspectives by **priority** (Critical-leaning / high-frequency first) — if `units × perspectives` exceeds the limit (1000), `workflow-template.js` splits perspectives into batches and executes them sequentially. Nothing is silently dropped.

Output: `perspectives: Array<{ id, name, precondition, focus, signals, fpNote, refs }>`.

### Step 3: Fan-out assessment via Dynamic Workflow

Pass `workflow-template.js` to Workflow via `scriptPath`, and inject the results of Steps 1 & 2 into `args`:

```
Workflow({
  scriptPath: "<absolute-path>/.claude/skills/sast/workflow-template.js",
  args: { units, perspectives }
})
```

The script runs `pipeline(units, parallel-assess each unit across all perspectives, merge)` and returns structured FINDINGS. Concurrency is 16, budget is applied automatically. If the limit (1000) is exceeded, perspectives are split into batches and executed sequentially (nothing is silently dropped). The return value is `{ summary, units, findings }`.

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
| Pre-filtering perspectives based on unit tags          | No per-unit pre-filtering. Every perspective runs on every unit. Each agent reads the actual code and checks the perspective's `## Preconditions` — if not met, returns `findings: []`. This eliminates "missing tag → skipped perspective → missed vulnerability". |
| Tagging units with capability labels                   | Unit tags are not needed. Units only need `id`, `method`, `route`, `desc`, `files`. The workflow does not use tags for filtering. |
| Bundling endpoints together to reduce unit count        | Strictly follow 1 unit = 1 endpoint. Bundling endpoints with different attack surfaces increases missed findings. Excess agents are handled by batch-splitting. |
| Ignoring framework protections and mass-producing FPs  | Parameterized queries / automatic escaping / typed inputs are considered protections and are out of scope |
| Silently dropping skipped perspectives                 | Explicitly list them in the report's "Out of scope" section (No-silent-caps)                              |
| Stuffing multiple perspectives into one agent          | 1 agent = 1 perspective. This is the core of precision and FP reduction                                   |
| Reading all perspective files at once                  | Skip chapters for areas absent from the target (token efficiency)                                         |
