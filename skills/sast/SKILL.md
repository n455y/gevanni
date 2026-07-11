---
name: sast
description: Use when the user wants a white-box (source-code) security review of web application code — asking to find vulnerabilities, audit routes/handlers/controllers for security issues, or check code against OWASP ASVS/WSTG/CheatSheet. Trigger phrases include "run a security assessment", "check for vulnerabilities", "source code security review", "ASVS-compliant assessment", "audit endpoints for injection/auth/authz/crypto issues", "find vulnerabilities in this code".
---

# SAST

## Overview

White-box static analysis (SAST-style). Split the target web application's **source code** by routing/handler units, build a list of **unit × perspective** pairs (after README-area exclusion), then fan out one sub-agent per pair via Dynamic Workflow. The prompt places the **perspective block first and the unit second**, and pairs are sorted by perspective ID so adjacent agents share the perspective prefix (prompt-cache friendly). After fan-out, the main agent merges similar findings and checks for chained (combined) attacks. No dynamic testing is performed — dynamic assessment is complemented by the `gevanni` scanner.

**Core principle**: 1 sub-agent = 1 (assessment unit × perspective) pair. Keep the context small to increase detection precision and reduce false positives.

**Two modes** (ask the user which to use in Step 0):

- **standard** (default): build a unit × perspective pair list (README-area exclusion only), then fan out one sub-agent per pair. Precision-first, fewer false positives, but more agents / higher cost & time.
- **fast**: launch **one sub-agent per perspective** (max 133) and have each scan the **whole source code**. Faster and cheaper, but lower precision, more false positives, and a higher miss rate. Use for large codebases or quick triage.

## Prerequisites & Ethics

- **Authorized targets only**. Step 0 confirms the target and authorization (in-house code / CTF / commissioned penetration testing / learning samples, etc.). If unclear, confirm with the user before executing.
- **Static analysis only**. No requests are sent to external services, and no live environments are scanned.
- Findings represent "possibility". Areas where framework protections (parameterized queries, automatic escaping, typed inputs, etc.) are effective are basically out of scope. FPs are explicitly indicated by confidence level.

## Workflow

### Step 0: Confirm target & authorization

- Identify the directory/repository to be assessed.
- Confirm the authorization scope. If unclear, check with the user before proceeding.
- **Confirm the scan mode** before launching the workflow. Present the trade-off and let the user choose:
  - **standard** (default): precision-first, fewer FPs, but more agents / higher cost & time.
  - **fast**: one agent per perspective (max 133) scanning the whole source — faster/cheaper, but lower precision, more FPs, higher miss rate.
  - If the user doesn't specify, default to **standard**. Record the choice as `mode` (`standard` | `fast`).
  - **Skip this prompt if a `mode` was already supplied by the caller** (e.g., when invoked from the `scan` skill, which confirms the mode in its own Step 0). Honor the supplied value and go straight to the matching step.

### Step 1: Source analysis and unit splitting (standard only)

Extract routing/handlers to create **assessment units**. (Fast mode skips this — go to Step 2-fast.)

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
- `files`: list of source files (relative to repo root) that contain the handler code
- `deps`: other source files called by the handler (for context)

**Splitting strategy**: 1 unit = 1 endpoint. **Never bundle endpoints together.** Each endpoint has a different attack surface.

Output: `units: Array<{ id, method, route, desc, files, deps? }>`.

### Step 2-standard: Build unit × perspective pair list (via a dedicated sub-agent)

Launch **one dedicated sub-agent** (via the Agent tool) to build the pair list. Pass it:
- `units` from Step 1
- the full index content of `perspectives/README.md` (read it first and pass it in the prompt)

**The sub-agent's task:**
1. Scan the README index and exclude perspectives for areas **absolutely absent** from the target code, using the same loose, area-based criteria as the README scan:
   - No GraphQL → skip GraphQL perspectives
   - No file upload → skip upload perspectives
   - No OAuth → skip OAuth perspectives
   - No SAML → skip SAML perspectives
   - No gRPC/WebSocket → skip the corresponding perspectives
   - (Follow the README's chapter structure.)
2. **Always return the excluded perspectives explicitly** as `droppedPerspectives: Array<{ povId, reason }>` (No-silent-caps — these go into the report's Out-of-scope section).
3. Return the cartesian product of **all remaining perspectives × all units** as the pair list. Do **not** do per-unit precondition filtering — only README-area exclusion.

**Sub-agent output contract:**
```json
{
  "pairs": [ { "unitId": "U01", "povId": "P1" }, ... ],
  "droppedPerspectives": [ { "povId": "P4", "reason": "No GraphQL endpoints found" }, ... ]
}
```

### Step 2-fast: Load perspectives + collect source files (fast only)

Fast mode skips unit splitting. Instead:
- Read `perspectives/README.md` and exclude perspectives for areas **absolutely absent** from the target code (same loose README-area criteria as Step 2-standard). Keep a list of excluded perspectives for the Out-of-scope section.
- Read each remaining `P<seq>-<name>.md` and assemble `{ id, name, precondition, focus, signals, fpNote, refs }`.
- Collect a **`sourceFiles`** list — target source files under the assessment directory (relative paths from repo root), excluding build artifacts/dependencies (`node_modules, .git, dist, build, .next, vendor, target, __pycache__, *.min.js, *.map, package-lock.json, yarn.lock, .terraform, coverage`).

Output: `perspectives: Array<{...}>` and `sourceFiles: Array<relative-path>`.

### Step 3: Launch the Workflow (split if pairs > 1000)

**standard:**
- If `pairs.length <= 1000`, launch `workflow-standard.js` once:
  ```
  Workflow({
    scriptPath: "<absolute-path>/skills/sast/workflow-standard.js",
    args: { pairs, units, perspectives }
  })
  ```
  (`perspectives` here = the perspective objects for the povIds that survived exclusion; assemble them by reading the corresponding `P<seq>-*.md` files, or have the Step 2 sub-agent return them.)
- If `pairs.length > 1000`, **split `pairs` into chunks of ≤ 1000** and launch `workflow-standard.js` **multiple times sequentially** (workflow self-recursion is limited to 1 level, so splitting must happen on the main-agent side). Concatenate each run's `findings` into one array. Log the per-chunk counts.

**fast:**
```
Workflow({
  scriptPath: "<absolute-path>/skills/sast/workflow-fast.js",
  args: { perspectives, sourceFiles }
})
```
Perspectives max out at 133 < 1000, so no splitting is needed.

Both templates return `{ summary, units, findings }` with the same shape. `summary.mode` is `'standard'` or `'fast'`.

### Step 4: Fan-out assessment (inside the Workflow)

This runs inside the Dynamic Workflow (no main-agent action needed):
- **standard**: `workflow-standard.js` sorts `pairs` by `povId`, then runs one sub-agent per pair. Each prompt places the **perspective block first, then the unit block** (cache-friendly). No precondition self-check — README-area exclusion already guaranteed applicability.
- **fast**: `workflow-fast.js` runs one sub-agent per perspective, scanning the whole source.

### Step 5: Merge similar findings (main agent)

The main agent takes all `findings` (concatenated across workflow chunks in standard mode) and **merges similar findings into one**:
- Merge criterion: same `povId` **AND** same or adjacent `location` (same function / same file, nearby lines).
- When merging: adopt the highest severity/confidence among the merged set; aggregate the multiple evidence/location snippets into the surviving finding.
- **Record the pre-merge count → post-merge count** (No-silent-caps).
- This requires LLM judgment — do it directly in the main-agent context (not pure code).

### Step 6: Check for chained (combined) attacks (main agent)

The main agent reviews the merged findings and looks for **chained attacks** that combine multiple findings into a more severe exploit:
- Examples: SSRF + internal metadata endpoint exposure; IDOR + information disclosure; XXE + SSRF; auth bypass + privilege escalation.
- Add each chain as a **new finding** (often higher severity). In its `evidence`, cite the originating findings' `povId`/`location`.
- If no plausible chain exists, skip this step — do not fabricate.

### Step 7: Generate the integrated report (main agent)

Feed the merged findings (Step 5) + chained-attack findings (Step 6) into `report-template.md`, generate a single Markdown report, and save & present it. In the **Out-of-scope section**, list every perspective excluded in Step 2 (`droppedPerspectives`) — no silent caps.

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
| Per-unit precondition filtering in the Step 2 sub-agent | Step 2 does README-area exclusion ONLY (GraphQL/OAuth/upload absent → skip). Do not drop pairs by per-unit precondition judgment — the area-based exclusion already guarantees applicability. |
| Silently dropping excluded perspectives                | The Step 2 sub-agent MUST return `droppedPerspectives`; list them in the report's Out-of-scope section (No-silent-caps) |
| Bundling endpoints together to reduce unit count        | Strictly follow 1 unit = 1 endpoint. Bundling endpoints with different attack surfaces increases missed findings. |
| Ignoring framework protections and mass-producing FPs  | Parameterized queries / automatic escaping / typed inputs are considered protections and are out of scope |
| Stuffing multiple perspectives into one agent          | 1 agent = 1 (unit × perspective) pair (standard) or 1 perspective (fast). This is the core of precision and FP reduction |
| Launching one giant Workflow when pairs > 1000          | Split `pairs` into chunks of ≤ 1000 and launch `workflow-standard.js` multiple times sequentially. Workflow self-recursion is limited to 1 level, so splitting happens on the main-agent side. |
| Putting the unit block before the perspective block in the prompt | Standard prompt order is **perspective first, unit second** (cache-friendly). `workflow-standard.js` already does this. |
| Forgetting the exclude patterns in fast mode           | Always exclude `node_modules`/`dist`/`.git`/etc. in `sourceFiles`. Otherwise agents read irrelevant files and cost explodes. |
| Treating fast mode as one "catch-all" agent            | Even in fast mode, keep **1 agent = 1 perspective**. Each agent just scans the whole source for its single perspective. |
| Fabricating `unitId`/`route` in fast mode              | Fast mode scans the whole source; attribution is best-effort. If unclear, omit `unitId`/`route` and rely on `location` (file:line). |
| Skipping the merge (Step 5) or chain check (Step 6)    | Both are main-agent steps after fan-out. Merging reduces noise; chain checks catch escalated attacks neither finding shows alone. |
