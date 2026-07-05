---
name: scan
description: Use when the user wants a comprehensive security assessment combining both dynamic (DAST) and static (SAST) analysis — asking for a "full scan", "complete security audit", "combined assessment", "run both DAST and SAST", or wants to correlate black-box findings with source-code review to identify detection gaps and improve future scan coverage.
---

# Scan (DAST + SAST Orchestration)

## Overview

Orchestrate parallel DAST and SAST scans, cross-reference findings to identify detection gaps, generate missing DAST signature plugins for future coverage, and produce a unified security report.

**Core principle**: DAST and SAST are complementary. DAST finds what's actually exploitable from the outside; SAST finds what's theoretically vulnerable in the code. Running both in parallel and correlating results gives the most complete picture — and the gaps teach us what to add to the scanner.

## When to Use

- User asks for a "full scan" or "comprehensive security assessment"
- User wants both dynamic (black-box) and static (white-box) analysis
- User wants to improve future DAST detection by writing plugins for what was missed
- User wants to cross-validate: do the SAST findings actually exist at runtime?

## Prerequisites

- **Running application** accessible via HTTP/HTTPS (for DAST)
- **Source code** of the same application (for SAST)
- **Authorization** for both dynamic testing and source review
- Node.js >= 24.12.0 (for gevanni scanner)
- Both `dast` and `sast` skills available

## Workflow

### Step 0: Collect all inputs upfront

Both sub-skills need user input. Collect everything before dispatching so the parallel agents can run without interruption:

| Input | DAST | SAST |
|-------|------|------|
| Target URL | **Required** | — |
| Source directory | — | **Required** |
| OpenAPI spec path | Optional | — |
| Authorization scope | **Required** | **Required** |

Confirm authorization for both target URL and source code. If the user only provides one (e.g., only a URL, no source), ask for the missing piece — a combined scan requires both.

### Step 1: Parallel scan execution

SAST は内部で Dynamic Workflow を使用しており、Workflow ツールはメインコンテキストでのみ利用可能なため、**SAST はメインコンテキストで `/sast` を実行し、DAST のみ Agent ツールで並列起動する**。

**実行パターン**:

1. **DAST を Agent ツールでバックグラウンド起動**（`run_in_background: true`）:
   ```
   Agent(label: "dast-scan", run_in_background: true):
     "DAST スキャンを実行して。ターゲットURL: <target-url>。
      /workspace/skills/dast/SKILL.md のワークフローに従うこと。
      完了したら findings を構造化した JSON で返して。"
   ```

2. **SAST をメインコンテキストで実行**:
   ```
   /sast を起動し、<source-dir> に対して静的解析を実行する。
   ```

3. DAST のバックグラウンドエージェントが完了するのを待つ（`<task-notification>` で通知される）。

この方法で、SAST（メイン）と DAST（バックグラウンド）が実質的に並列実行される。

**DAST agent** follows `/workspace/skills/dast/SKILL.md`:
- Generate/select scenarios → create config.json → execute `gevanni scan` → AI deep inspection
- Output: structured findings with vulnerability type, severity, evidence (request/response), confidence

**SAST agent** follows `/workspace/skills/sast/SKILL.md`:
- Source analysis → unit splitting → load perspective catalog → fan-out via Workflow → integrated report
- Output: structured findings with povId, severity, confidence, location (file:line), evidence (code snippet), remediation

Both agents produce their findings in a structured format. Wait for both to complete before proceeding.

### Step 2: Gap analysis — cross-reference findings

Map SAST findings to DAST findings to categorize each:

#### Mapping rules

A SAST finding **matches** a DAST finding when:
- Same vulnerability class (e.g., SAST `P38-ReflectedXSS` ↔ DAST `signature:reflected-xss`)
- Same endpoint/route (SAST `location` ↔ DAST `parameter.location`)
- OR same parameter/input vector

Use this mapping table for vulnerability class equivalence:

| SAST Perspective | DAST Signature | Category |
|------------------|---------------|----------|
| P38-ReflectedXSS | signature:reflected-xss | injection |
| P39-StoredXSS | (multi-step, not directly detectable) | — |
| P40-DOMXSS | (client-side only) | — |
| P18-SQLi | signature:sqli-error, signature:sqli-boolean, signature:sqli-diff, signature:sqli-time, signature:sqli-union | injection |
| P19-LDAP-Injection | signature:ldap-injection | injection |
| P20-OS-Command-Injection | signature:os-command-injection | injection |
| P21-Path-Traversal | signature:path-traversal | injection |
| P22-SSTI | signature:ssti | injection |
| P23-XXE | signature:xxe-injection | injection |
| P24-CRLF-Injection | signature:crlf-injection | injection |
| P25-NoSQL-Injection | signature:nosql-injection, signature:nosql-boolean, signature:nosql-diff | injection |
| P26-XPath-Injection | signature:xpath-injection | injection |
| P27-SSI-Injection | signature:ssi-injection | injection |
| P28-Prototype-Pollution | signature:prototype-pollution | injection |
| P41-Open-Redirect | (not yet a built-in signature) | aux |

For SAST perspectives not listed above (auth, session, crypto, config, logging, etc.), there is typically **no corresponding DAST signature** — these are architecture/logic concerns that don't produce HTTP-observable signatures.

#### Categorization output

For each finding across both scans, assign one of:

| Category | Meaning | Action |
|----------|---------|--------|
| `both` | Found by both DAST and SAST | **Confirmed** — highest confidence |
| `sast_only` | Found by SAST, missed by DAST | **Gap** — analyze for plugin generation |
| `dast_only` | Found by DAST, missed by SAST | **SAST gap** — flag as potential SAST perspective gap or false positive |

### Step 3: Plugin generation for DAST-detectable gaps

For each `sast_only` finding, classify whether a DAST signature plugin can detect it.

#### Detectability decision tree

```
sast_only finding
  ├─ Is it an injection class with HTTP-observable response? (SQLi error, XSS reflected, CMDi, path traversal, SSTI, XXE, CRLF, LDAP, NoSQL error)
  │   └─ YES → DAST-DETECTABLE → Generate plugin
  ├─ Is it a boolean/blind injection detectable via response diff? (boolean SQLi, NoSQL boolean)
  │   └─ YES → DAST-DETECTABLE → Generate plugin (diff-based)
  ├─ Is it time-based? (time-based SQLi, blind timing)
  │   └─ YES → NOT DETECTABLE → Skip (timing side-channels are unreliable in automated scanners; requires controlled lab conditions)
  ├─ Is it a business logic / authorization issue?
  │   └─ YES → NOT DETECTABLE → Skip (requires semantic understanding of application logic)
  ├─ Is it a cryptographic / configuration weakness?
  │   └─ YES → NOT DETECTABLE → Skip (not observable via black-box request/response patterns)
  ├─ Is it a multi-step workflow vulnerability? (stored XSS, second-order injection)
  │   └─ YES → NOT DETECTABLE → Skip (requires multi-step state tracking beyond current scanner capabilities)
  └─ Is it a client-side only issue? (DOM XSS, CSP gaps)
      └─ YES → NOT DETECTABLE → Skip (requires browser execution context)
```

**DAST-detectable → generate a plugin file** at `<cwd>/.gevanni/plugins/custom-<vuln-type>.ts`.

**NOT detectable → document** in the integrated report's "Coverage gaps" section with the reason for skipping.

#### Plugin generation template

Generated plugins follow the `SignaturePluginBase` pattern. Place them in `.gevanni/plugins/` relative to the scan working directory, then reference them in `config.json`:

```json
{
  "plugins": [
    ":builtin:",
    "./.gevanni/plugins/custom-sqli-error.ts",
    "./.gevanni/plugins/custom-xss-reflected.ts"
  ]
}
```

**Template reference**: See `plugin-template.ts` in this skill directory for the base class structure. Each generated plugin must:

1. **Extend** `MutationFilteredSignaturePlugin` (from `gevanni`'s plugin API) for payload-based checks, or `SignaturePluginBase` for response-analysis checks
2. **Define** `name` as `signature:custom-<kebab-case-vuln-type>`
3. **Define** `groups` with the appropriate `SignatureGroupId`
4. **Implement** `runAudit(context)`: send crafted payload(s), analyze response, return `{ vulnerable, evidence, request, response }`
5. **Accept constructor options** for configurable thresholds/payloads

**Example — custom error-based SQLi plugin for a specific parameter pattern**:

```typescript
// .gevanni/plugins/custom-sqli-error.ts
import { SignatureGroupId } from "../../types/branded.ts";
import type { Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "../signature/mutation-filtered.ts";

const CUSTOM_ERROR_PATTERNS: RegExp[] = [
  /unclosed quotation mark/i,
  /syntax error in string literal/i,
  /unexpected end of SQL command/i,
];

export default class CustomSqliErrorPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:custom-sqli-error";
  protected readonly groups = [SignatureGroupId("sqli")];
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const payload = BuiltinPayload.String("' OR '1'='1");
    const result = await replay([
      parameter.createMutation(payload, BuiltinMutationType.AppendValue),
    ]);
    const allExchanges: Exchange[] = result.allExchanges;
    const matches = allExchanges.filter((ex) =>
      CUSTOM_ERROR_PATTERNS.some((p) =>
        p.test(ex.response.body?.toString() ?? "")
      ),
    );
    return {
      vulnerable: matches.length > 0,
      evidence: {
        judgmentId: "custom-sql-error-pattern",
        exchanges: allExchanges,
        evidenceExchanges: matches,
      },
      request: result.exchange.request,
      response: result.exchange.response,
    };
  }
}
```

**After generating plugins**, update the DAST config to include them and note that re-running the scan will now catch these previously missed vulnerabilities.

### Step 4: Integrated report

Merge both scan results into a single unified report. The report has 6 sections:

#### 1. Executive Summary

- Target URL + source directory
- Scan timestamps (DAST and SAST)
- Combined vulnerability counts by severity (Critical/High/Medium/Low/Info)
- Correlation summary: N confirmed by both, M DAST-only, K SAST-only
- Plugin generation summary: N plugins generated, M gaps documented as not detectable

#### 2. Correlation Matrix

Table mapping each vulnerability class across both scans:

| Vulnerability Class | SAST | DAST | Status |
|---------------------|------|------|--------|
| SQL Injection | ✓ (3 findings) | ✓ (2 findings) | Partial — 1 SAST-only gap, plugin generated |
| Reflected XSS | ✓ (1 finding) | ✓ (1 finding) | Confirmed |
| Command Injection | ✓ (1 finding) | — | SAST-only — not detectable (blind, no output) |
| ... | | | |

#### 3. Confirmed Findings (both)

Findings detected by both scans — highest confidence. For each:
- Vulnerability type, severity, location (endpoint + code file:line)
- DAST evidence (request/response excerpts)
- SAST evidence (code snippet + analysis)
- Remediation

#### 4. DAST-Only Findings

Findings DAST caught but SAST missed. These may indicate:
- SAST perspective gaps (missing perspective file for this vuln class)
- Runtime/config issues not visible in source code
- False positives in DAST (flag for manual verification)

#### 5. SAST-Only Findings (with plugin status)

Findings SAST caught but DAST missed. Each entry includes:
- SAST finding details
- Detectability classification
- **If detectable**: link to generated plugin file, instructions for re-running DAST
- **If not detectable**: reason, suggested alternative verification method (manual testing, code review)

#### 6. Coverage & Limitations

- DAST: endpoints tested, scenarios used, plugins active
- SAST: units assessed, perspectives applied, perspectives skipped (with reasons)
- Gap summary: what neither scan covers
- Recommendations for next scan cycle (include generated plugins, add scenarios for missed endpoints)

## Output Contract

After the scan completes, the user receives:

1. **Integrated report** (Markdown) — saved to `<cwd>/.gevanni/scan-report-<date>.md`
2. **Generated plugins** — saved to `<cwd>/.gevanni/plugins/custom-*.ts`
3. **Updated DAST config** — `config.json` with new plugin references (or instructions to add them)
4. **Raw scan outputs** preserved for reference:
   - DAST: JSON report from `gevanni scan --reporter json`
   - SAST: Markdown report from sast workflow

## Common Mistakes

| Pitfall | Correct approach |
|---------|-----------------|
| Running scans sequentially instead of parallel | DAST and SAST are independent — always run in parallel for wall-clock efficiency |
| Generating plugins for everything SAST finds | Only generate for injection classes with observable HTTP responses; skip timing/blind/logic/config issues |
| Not updating config.json after generating plugins | Plugins must be referenced in `"plugins"` array to take effect on next scan |
| Treating detection gaps as failures | Gaps are expected — they're the input to improving scanner coverage. Document and move on |
| Assuming SAST findings are always exploitable | Cross-reference with DAST; SAST-only findings may be false positives or protected by runtime guards |
| Not collecting all inputs before dispatching | Both agents need different inputs — gather URL, source dir, and auth upfront to avoid mid-scan interruptions |
| Skipping the detectability classification | Every SAST-only finding must be explicitly classified as detectable or not with a reason — no silent skips |
| Using Workflow for scan orchestration | SAST already uses Dynamic Workflow internally. Nesting is not supported. Use Agent tool for parallel dispatch. |

## Cross-References

- **DAST skill**: `/workspace/skills/dast/SKILL.md` — dynamic scan workflow and gevanni CLI
- **SAST skill**: `/workspace/skills/sast/SKILL.md` — static analysis workflow and perspective catalog
- **Plugin architecture**: `/workspace/skills/dast/src/core/plugin.ts` — plugin interface
- **Signature base**: `/workspace/skills/dast/src/plugins/signature/base.ts` — `SignaturePluginBase`
- **Plugin template**: `plugin-template.ts` in this directory — reference for generated plugins (base class structure, detection patterns, constructor options)
