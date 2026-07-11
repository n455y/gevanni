# gevanni

Web application vulnerability scanner that runs as a Claude Code plugin, combining DAST (dynamic analysis) and SAST (static analysis) in parallel with cross-referenced findings and detection gap analysis.

## Requirements

- **Node.js >= 24.12.0** — native TypeScript execution (type stripping)

## Install

```bash
# Add the marketplace
claude plugin marketplace add n455y/gevanni

# Install the plugin
claude plugin install gevanni
```

## `/gevanni:scan`

The main skill. Runs DAST and SAST in parallel, cross-references the results, and outputs a unified report.

```bash
/gevanni:scan scan ./src, the app is running at http://localhost:3000
```

### What it does

1. **Parallel scan** — DAST (dynamic) and SAST (static) run simultaneously
2. **Gap analysis** — maps findings from both scans into three categories:
   - **Confirmed** — detected by both (highest confidence)
   - **SAST-only** — found statically but missed dynamically → auto-generate signature plugin or document why it's undetectable
   - **DAST-only** — found dynamically but missed statically → SAST perspective gap or potential false positive
3. **Plugin generation** — for SAST-only findings detectable via HTTP responses, auto-generates signature plugins (output to `.gevanni/plugins/autoload/`)
4. **Unified report** — correlation matrix + all findings across both scans in a single report

Internally orchestrates the sub-skills below.

## Sub-skills

### `/gevanni:dast`

Black-box dynamic analysis against a running web application. Sends real HTTP requests guided by an OpenAPI spec and detects vulnerabilities via signature matching and AI deep inspection.

- **47 built-in signatures** — SQL Injection (error/boolean/diff/time/union), NoSQL Injection, Reflected XSS, Path Traversal, SSTI, SSI, XXE, LDAP/CRLF/XPath Injection, OS Command Injection, Prototype Pollution, Zip Slip
- **Plugin architecture** — `:builtin:` core + autoload (`plugins/autoload/`) + marketplace
- **AI deep inspection** — re-analyzes undetected jobs (information disclosure, misconfigurations, blind injection)
- **Multi-reporter** — `console` + `json`

### `/gevanni:sast`

White-box static analysis. Splits endpoints into individual units and evaluates each against **133 security perspectives** (1 unit × 1 perspective) for high precision. Covers injection, auth, session, crypto, config, logging, file handling, aligned with OWASP ASVS / WSTG / CheatSheet.

### `/gevanni:generate-scenario [type]:[path]`

Generates `x-gevanni-scenarios` from API specs or source code. Serves as input for the DAST and Scan skills.

- Supported formats: `openapi`
- Output: `.gevanni/scenarios/`

## Architecture

```
gevanni/
├── bin/gevanni.js          # CLI entry point
├── src/
│   ├── cli/                # Command definitions (scan, proxy, validate)
│   ├── commands/           # Audit/replay/report/mutation etc.
│   ├── config/             # Config + plugin loader
│   ├── core/               # Plugin interface, orchestrator, event/command bus
│   ├── http/               # HTTP sender
│   ├── plugins/
│   │   ├── proxy/          # HTTP/HTTPS proxy
│   │   └── signature/      # 47 built-in signatures
│   └── types/              # Shared type definitions
└── examples/
```

## Examples

`examples/juiceshop/` contains a setup script for OWASP Juice Shop via Docker:

```bash
cd examples/juiceshop
./setup.sh                       # clone → build → run (http://localhost:3000)
JUICE_SHOP_PORT=8080 ./setup.sh  # custom port
```

```bash
/gevanni:scan full scan, the app is at http://localhost:3000
```

## Development

```bash
cd skills/dast && npm ci
npm test              # vitest (140 source files, 46 test files)
npm run typecheck     # tsc --noEmit
npm run gevanni -- scan -s openapi:./spec.yaml
```

## CLI (advanced)

Also usable directly as a CLI:

```bash
npm install -g gevanni
gevanni scan -s openapi:./spec.yaml --reporter json
gevanni scan --config ./.gevanni/config.json --concurrency 5
```

```ts
import { builtinPluginFactories } from "gevanni";
```

## License

See the LICENSE file.
