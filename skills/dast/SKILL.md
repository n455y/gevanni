---
name: dast
description: Use when the user wants a black-box (dynamic) security assessment of a running web application — asking to scan a live target, test endpoints for vulnerabilities, or perform active security testing. Trigger phrases include "scan this URL", "run DAST against", "test the application", "security scan", "penetration test", "check for vulnerabilities on this site", "dynamic analysis".
---

# DAST

## Overview

Black-box dynamic analysis (DAST-style). Launch the `gevanni` scanner against a **running web application** to actively test endpoints for security vulnerabilities by sending real HTTP requests and analyzing responses. Unlike SAST (static analysis), DAST exercises the live application to discover runtime issues, configuration problems, and business logic flaws.

**Core principle**: Automated vulnerability scanning via OpenAPI specification or intelligent crawling, with multi-vector attack simulation (injection, authentication bypass, misconfigurations, etc.).

## Prerequisites & Setup

### Target Requirements

- **Live application** with accessible HTTP/HTTPS endpoints
- **Authorization scope**: You must have permission to scan the target (in-house apps / CTF / commissioned pentesting / local test environments)
- **OpenAPI specification (recommended)**: For comprehensive coverage, provide an OpenAPI/Swagger spec YAML/JSON file

### Environment Setup

The `gevanni` scanner runs as a Node.js CLI tool. Before executing DAST:

```bash
# Navigate to the dast skill directory
# (Typically: ~/.claude/plugins/gevanni/skills/dast or project/.claude/skills/dast)
cd <path-to-dast-skill>

# Install dependencies (clean install from package-lock.json)
npm ci

# Verify installation
npm run gevanni -- --help
```

### Requirements

- **Node.js >= 24.12.0** (native TypeScript execution with type stripping)
- **Network access** to target application
- **Sufficient memory** for large-scale scans (targets with many endpoints)

### Ethics

- **Authorized targets only**. Confirm authorization scope before scanning.
- **Rate limiting**: Be mindful of production systems; may require throttle configuration.
- **Findings are indicators**: Like SAST, results are "potential vulnerabilities" requiring validation.
- **No silent caps**: Always report what was tested and what was excluded from scope.

## Workflow

### Step 0: Confirm target & authorization

- Identify the target URL/base path
- Confirm authorization (development/staging environment, bug bounty scope, etc.)
- Check if OpenAPI spec is available

### Step 1: Generate scenarios via generate-scenario (openapi)

Once setup is complete, prepare the scenario input. The scenario directory is **`<cwd>/.gevanni/scenarios`**, where `<cwd>` is the directory from which this skill was invoked.

#### Step 1a: Check for existing scenarios

List `<cwd>/.gevanni/scenarios` (e.g. `*.yaml` / `*.yml`).

- **If scenario file(s) already exist**, ask the user to choose one of:
  1. **Reuse** — use one of the existing scenarios as-is (skip generation)
  2. **Regenerate & overwrite** — pick one existing scenario, regenerate it, and overwrite that file
  3. **Generate fresh** — create a brand-new scenario without touching existing files
- **If no scenarios exist**, proceed directly to generation (Step 1b).

#### Step 1b: Generate scenarios (if option 2 or 3, or no existing scenarios)

Invoke the `generate-scenario` skill (same `gevanni` plugin) with the `openapi` type:

```
# Generate x-gevanni-scenarios from application source code
/gevanni:generate-scenario openapi:./src

# Or from an existing OpenAPI spec file
/gevanni:generate-scenario openapi:./spec.yaml
```

If the user chose option 1 (Reuse), skip generation and use the selected scenario file directly as the scan input.

This produces `x-gevanni-scenarios` definitions in the OpenAPI 3.0 spec, which become the scan input.

#### Step 1c: Generate config.json

After scenario generation, create `./.gevanni/config.json`. This is the scan configuration used in Step 2 — scenarios and concurrency are read from here, so the scan command stays simple.

1. **Identify the scenario file** that was just generated (or selected for reuse)
2. **Create config.json** at `<cwd>/.gevilli/config.json` with this template:

```json
{
  "concurrency": 3,
  "plugins": [":builtin:"],
  "scenarios": [
    {
      "type": "openapi",
      "file": "../.gevanni/scenarios/<scenario-file-name>.yml"
    }
  ],
  "logLevel": "info"
}
```

Replace `<scenario-file-name>` with the actual scenario filename from Step 1b.

**Important — file paths are relative to configDir**: The `file` field is resolved relative to the directory containing config.json (i.e. `<cwd>/.gevilli`), not the current working directory. Since scenarios are generated under `<cwd>/.gevanni/scenarios/`, the path from `.gevilli/` is `../.gevanni/scenarios/...`. If unsure, use an absolute path instead.

### Step 2: Execute scan with appropriate plugins

The scan command supports two modes:

**Mode 1: Using config.json (recommended)**

Run the scan using the config.json generated in Step 1c:

```bash
npm run gevanni -- scan --config ./.gevanni/config.json
```

**Mode 2: Direct CLI options (without config)**

```bash
npm run gevanni -- scan \
  -s openapi:./.gevanni/scenarios/<scenario-file>.yml \
  --concurrency 3
```

**CLI options override config values:**

When using `--config`, you can still override specific values via CLI:

```bash
npm run gevanni -- scan --config ./.gevanni/config.json --concurrency 10
# Uses concurrency=10 from CLI, not config.concurrency
```

**Priority:** CLI options > config file > defaults

**Available options:**

- `--config <path>`: Config file path
- `-s, --scenario <name>:<path>`: Scenario source (repeatable)
- `-r, --reporter <name[:option]>`: Reporter to use (repeatable, e.g., `--reporter json:report.json`). Defaults to `console` when omitted.
- `--concurrency <n>`: Parallel workers
- `--verbose`: Debug logging
- `--quiet`: Minimal logging

### Step 3: Collect and analyze results

The scanner outputs structured findings with:

- Vulnerability type and severity
- Affected endpoint/path
- Evidence (request/response excerpts)
- Confidence level
- Remediation guidance

### Step 4: Report generation

Reports are generated automatically at the end of `gevanni scan`. You can also regenerate reports from saved scan results using the `report` command.

```bash
# Regenerate report from saved scan results (console only, default)
gevanni report <scanId> --config ./.gevilli/config.json

# Regenerate with JSON reporter
gevanni report <scanId> --config ./.gevilli/config.json --reporter json

# Regenerate with custom output path
gevanni report <scanId> --config ./.gevilli/config.json --reporter json:security-report.json
```

**Report output options:**

- **Console reporter** (default): Prints findings to terminal with severity ratings and evidence
- **JSON reporter**: Outputs structured JSON to `gevanni-report-{scanId}.json` (default) or a custom path

**Specifying reporters:**

```bash
# Single reporter (console is default when omitted)
gevanni scan --config ./.gevanni/config.json

# Single reporter with custom output
gevanni scan --config ./.gevanni/config.json --reporter json:scan-result.json

# Multiple reporters simultaneously
gevanni scan --config ./.gevanni/config.json --reporter json:report.json --reporter console
```

Reporters can also be configured via `config.json` plugin options (legacy, for JSON output path):

```json
{
  "plugins": [
    {
      "file": "./skills/dast/src/plugins/reporter/json-reporter.ts",
      "options": {
        "outputPath": "security-report.json"
      }
    }
  ]
}
```

**Report contents:**
- Scan ID, status, and timing
- Per-job findings (vulnerable/safe/error)
- Summary statistics (total jobs, vulnerable count, safe count, errors)
- Evidence excerpts for vulnerabilities (request/response pairs)

## Output contract

The scan results include:

1. **Executive summary**: Target, scan time, endpoints tested, vulnerability counts by severity
2. **Risk matrix**: Findings sorted by severity (Critical/High/Medium/Low/Info)
3. **Detailed findings** per vulnerability:
   - Type (e.g., SQL Injection, XSS, CORS misconfiguration)
   - Location (endpoint + HTTP method)
   - Evidence (malicious payload sent + response snippet showing vulnerability)
   - Severity & confidence
   - Remediation steps
   - References (OWASP, WSTG, CWE)
4. **Coverage report**: What was tested, what was excluded, scan limitations

## Common Mistakes

| Common pitfall                               | Correct approach                                               |
| -------------------------------------------- | -------------------------------------------------------------- |
| Scanning production without authorization    | Always confirm scope; use dev/staging when possible            |
| No OpenAPI spec → poor coverage              | Provide spec or configure crawl depth carefully                |
| Ignoring rate limits → DoS on target         | Set appropriate `--concurrency` and `--timeout`                |
| Missing silent caps in reporting             | Explicitly list untested endpoints/plugins                     |
| Treating automated scans as comprehensive    | DAST is one layer; combine with SAST and manual testing        |
| Running without understanding target context | Adjust plugins for tech stack (e.g., GraphQL-specific plugins) |

## Integration with SAST

DAST and SAST are complementary:

- **SAST**: Source code analysis, finds potential vulnerabilities before runtime
- **DAST**: Runtime testing, discovers issues only visible in live execution

For comprehensive security assessment, run both:

```bash
# First, SAST on source code
/gevanni:sast ./src

# Then, DAST on running application
/gevanni:dast https://app.example.com -s openapi:./spec.yaml
```
