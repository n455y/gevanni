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

### Step 1: Confirm target & authorization

- Identify the target URL/base path
- Confirm authorization (development/staging environment, bug bounty scope, etc.)
- Check if OpenAPI spec is available

### Step 2: Generate scenarios via generate-scenario (openapi)

Once setup is complete, prepare the scenario input. The scenario directory is **`<cwd>/.gevanni/scenarios`**, where `<cwd>` is the directory from which this skill was invoked.

#### Step 2a: Check for existing scenarios

List `<cwd>/.gevanni/scenarios` (e.g. `*.yaml` / `*.yml`).

- **If scenario file(s) already exist**, ask the user to choose one of:
  1. **Reuse** — use one of the existing scenarios as-is (skip generation)
  2. **Regenerate & overwrite** — pick one existing scenario, regenerate it, and overwrite that file
  3. **Generate fresh** — create a brand-new scenario without touching existing files
- **If no scenarios exist**, proceed directly to generation (Step 2b).

#### Step 2b: Generate scenarios (if option 2 or 3, or no existing scenarios)

Invoke the `generate-scenario` skill (same `gevanni` plugin) with the `openapi` type:

```
# Generate x-gevanni-scenarios from application source code
/gevanni:generate-scenario openapi:./src

# Or from an existing OpenAPI spec file
/gevanni:generate-scenario openapi:./spec.yaml
```

If the user chose option 1 (Reuse), skip generation and use the selected scenario file directly as the scan input.

This produces `x-gevanni-scenarios` definitions in the OpenAPI 3.0 spec, which become the scan input.

#### Step 2c: Generate config.json

After scenario generation, create `./.gevanni/config.json`. This is the scan configuration used in Step 3 — scenarios, plugins, and concurrency are read from here, so the scan command stays simple.

1. **Identify the scenario file** that was just generated (or selected for reuse)
2. **Discover custom plugins** in `<cwd>/.gevanni/plugins/autoload/`:
   - Check if `<cwd>/.gevanni/plugins/autoload/` directory exists
   - If it exists, list all `*.ts` and `*.js` files (top-level only, non-recursive)
   - Each file becomes a plugin entry with the path `./plugins/autoload/<filename>` (resolved relative to configDir, i.e. `<cwd>/.gevanni/`)
   - If the directory doesn't exist or is empty, no custom plugins are added
3. **Create config.json** at `<cwd>/.gevanni/config.json` with this template:

```json
{
  "concurrency": 3,
  "plugins": [":builtin:", "./plugins/autoload/custom-auth.ts", "./plugins/autoload/rate-limiter.js"],
  "scenarios": [
    {
      "type": "openapi",
      "file": "../.gevanni/scenarios/<scenario-file-name>.yml"
    }
  ],
  "logLevel": "info"
}
```

- Replace `<scenario-file-name>` with the actual scenario filename from Step 2b
- Replace `./plugins/autoload/custom-auth.ts` and `./plugins/autoload/rate-limiter.js` with the actual files discovered in step 2 — always keep `:builtin:` as the first entry; add discovered plugin paths after it. If no custom plugins were found, use just `":builtin:"`
- Plugin paths are relative to configDir (`<cwd>/.gevanni/`), so `./plugins/autoload/foo.ts` resolves to `<cwd>/.gevanni/plugins/autoload/foo.ts`

**Important — file paths are relative to configDir**: The `file` and plugin paths are resolved relative to the directory containing config.json (i.e. `<cwd>/.gevanni`), not the current working directory. Since scenarios are generated under `<cwd>/.gevanni/scenarios/`, the path from `.gevanni/` is `../.gevanni/scenarios/...`. If unsure, use an absolute path instead.

### Step 3: Execute scan (scan + report in one shot)

The scan command runs the vulnerability scan and generates reports in a single execution via the `--reporter` option. Reports are produced at the end of the scan — no separate report step needed.

The scan command supports two modes:

**Mode 1: Using config.json (recommended)**

Run the scan using the config.json generated in Step 2c. Always include `--reporter json` to save a structured report alongside the default console output:

```bash
npm run gevanni -- scan --config ./.gevanni/config.json --reporter json
```

With a custom output path:

```bash
npm run gevanni -- scan --config ./.gevanni/config.json --reporter json:scan-result.json
```

Multiple reporters simultaneously:

```bash
npm run gevanni -- scan --config ./.gevanni/config.json --reporter json:report.json --reporter console
```

**Mode 2: Direct CLI options (without config)**

```bash
npm run gevanni -- scan \
  -s openapi:./.gevanni/scenarios/<scenario-file>.yml \
  --concurrency 3 \
  --reporter json
```

**CLI options override config values:**

When using `--config`, you can still override specific values via CLI:

```bash
npm run gevanni -- scan --config ./.gevanni/config.json --concurrency 10 --reporter json
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

**Reporter types:**

- **`console`** (default): Prints findings to terminal with severity ratings and evidence
- **`json`**: Outputs structured JSON to `gevanni-report-{scanId}.json` (default) or a custom path via `json:<path>`

### Step 4: Review results

The scan output (console + saved reports) includes structured findings with:

- Vulnerability type and severity
- Affected endpoint/path
- Evidence (request/response excerpts)
- Confidence level
- Remediation guidance

**Report contents (JSON):**

- Scan ID, status, and timing
- Per-job findings (vulnerable/safe/error)
- Summary statistics (total jobs, vulnerable count, safe count, errors, skipped)
- Evidence excerpts for vulnerabilities (request/response pairs with body in both `base64` and `utf8`)

### Step 5: AI Deep Inspection — analyze undetected jobs

**Purpose**: Signature-based detection (Step 3) only flags known vulnerability patterns. Many subtle issues — information disclosure, misconfigurations, unusual error handling, partial injection reflections — are reported as **safe** or **error** and ignored. This step uses AI to analyze the request/response logs of those undetected jobs, identify suspicious behavior, and perform additional deep-dive inspection.

#### Step 5a: Extract undetected jobs from the JSON report

Load the JSON report generated in Step 3 (e.g., `gevanni-report-<scanId>.json`). Each job in the `jobs` array has:

- `status`: `"completed"` | `"error"` | `"skipped"`
- `finding`: the detected result — `finding.vulnerable === false` means the signature didn't flag it
- `error`: error message if the job failed
- `signatureName`: which detection plugin ran
- `parameter`: which request parameter was tested (location, original value, allowed mutations)

Filter jobs where **deep inspection is needed**:

- `status === "completed"` AND `finding.vulnerable === false` → "safe" jobs
- `status === "error"` → "error" jobs

For large scans (100+ undetected jobs), prioritize:

1. **Error jobs first** — errors during testing may indicate the target crashed, timed out, or rejected the payload in an unusual way (potential DoS, WAF bypass, or parsing vulnerabilities)
2. **High-value parameter jobs** — parameters in auth headers, cookies, path segments, or GraphQL queries
3. **Interesting endpoint jobs** — admin paths, API endpoints, file upload/download, redirect endpoints

#### Step 5b: Analyze each candidate's request/response

For each undetected job, examine the `finding.request` and `finding.response` (for safe jobs) or the `error` message (for error jobs). Look for these suspicious patterns:

**Response body analysis** (check `finding.response.body.utf8`):

- **Error messages with internal details**: Stack traces, file paths (`/var/www`, `C:\`, `/home/`), SQL snippets, framework debug output
- **Server technology leaks**: Version numbers of servers, frameworks, or libraries in error pages
- **Reflected input in non-executable context**: User input echoed inside HTML comments, JavaScript strings, JSON values, or HTTP headers → potential for escalated injection
- **Unusual response structure**: JSON keys that look like debug flags (`debug: true`, `isAdmin: false`), internal IP addresses, database connection strings
- **Differential behavior**: For diff-based signatures, compare `evidence.exchanges` — even if the diff didn't hit the vulnerability threshold, significant structural changes in the response warrant investigation

**Response header analysis** (check `finding.response.headers`):

- **Server fingerprinting**: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` headers
- **CORS misconfiguration**: `Access-Control-Allow-Origin: *` with credentials, or reflecting the request's `Origin` header
- **Cache poisoning indicators**: `X-Cache: HIT` with user-controlled input in the cache key
- **Security header gaps**: Missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` on sensitive pages
- **Cookie attributes missing**: `Set-Cookie` without `HttpOnly`, `Secure`, or `SameSite`

**Status code anomalies**:

- `500` with detailed error → information disclosure
- `403` on parameter tampering → possible authorization bypass path
- `429` → rate limiting detected; try slower, varied timing
- `200` with empty body or `{"error": "..."}` → the app may be silently swallowing errors
- `302`/`301` with user-controlled redirect target → open redirect

**Timing patterns** (if the signature was time-based like `sqli-time`):

- Even if the timing plugin didn't flag it, response times >2x normal may indicate blind injection

#### Step 5c: Perform deep-dive inspection on suspicious items

For each item flagged as suspicious in Step 5b, craft additional probe requests to verify and escalate:

1. **Read the scenario file first**: The job's `scenarioId` links to a scenario file under `./.gevanni/scenarios/` (or wherever the scan was configured to load from). Read the scenario file to get the original endpoint definition:
   - Base URL, HTTP method, path, headers, query params, request body schema
   - Authentication/security scheme configuration
   - Multi-step flow (linked requests) — follow the whole chain to reproduce the exact request context
   - This is far more efficient than reverse-engineering from source code or guessing from a single request log

   **If the scenario looks wrong or inconsistent** with the actual application behavior (e.g., wrong base URL, missing parameters, auth not working), fall back to reading the application source code to understand the real endpoint structure.

2. **Formulate a follow-up request**: Using the scenario definition + the original `finding.request` as reference, modify the payload to test the specific hypothesis. Examples:
   - If a stack trace was leaked → try path traversal variants to read config files
   - If input was reflected in a JSON response → try JSONP callback injection or JavaScript hijacking
   - If headers leak server info → probe for known vulnerabilities of that version
   - If error messages contain SQL fragments → try UNION-based extraction

3. **Execute the probe**: Use `curl`, `httpie`, or a simple script to send the follow-up request. Record the full request and response.

4. **Document findings**: For each confirmed finding, record:
   - **Vulnerability type** (e.g., Information Disclosure, Open Redirect, Blind Injection)
   - **Severity** (Critical/High/Medium/Low/Info) based on impact
   - **Evidence**: the probe request and response showing the issue
   - **Remediation**: actionable fix guidance
   - **Confidence**: whether it was confirmed or needs manual verification

#### Step 5d: Integrate deep inspection results

Compile the deep inspection findings alongside the original scan results:

- Merge new findings into the overall vulnerability list
- Update the risk matrix with new severities
- Note in the coverage report that AI deep inspection was performed on N safe/error jobs
- Distinguish between automated findings (signature-based) and AI-discovered findings in the output

**Output**: A consolidated security report that includes both Step 3 automated findings AND Step 5 AI-discovered findings, with clear provenance for each.

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
| Ignoring rate limits → DoS on target         | Set appropriate `--concurrency`                                |
| Missing silent caps in reporting             | Explicitly list untested endpoints/plugins                     |
| Running without understanding target context | Adjust plugins for tech stack (e.g., GraphQL-specific plugins) |
