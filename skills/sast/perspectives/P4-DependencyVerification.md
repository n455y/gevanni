---
id: P4
name: DependencyVerification
refs: ASVS V10.x / WSTG-INFO-08 / CS: Dependency Management, Third Party JS
requires: []
---

# P4 — Dependency Verification

## Overview
Modern applications assemble the majority of their code from third-party dependencies — npm packages, PyPI modules, Maven artifacts, Go modules, RubyGems, Composer libraries, and CDN-hosted scripts. Each transitive dependency is an implicit grant of code execution inside the application's trust boundary. Dependency-verification failures fall into three root causes: **(1) unfixed known vulnerabilities** — a pinned (or floating) version carries an unpatched CVE; **(2) supply-chain compromise** — a typosquatted, hijacked, or maliciously-updated package is pulled in by a loose version range or a missing lockfile; and **(3) unverified integrity** — scripts/CDN assets are fetched without a checksum, signature, or Subresource Integrity (SRI) hash, so a MITM or compromised registry can swap the artifact. The category (OWASP A06:2021 — Vulnerable and Outdated Components, plus A08:2021 — Software and Data Integrity Failures) is consistently in the top causes of real-world breaches.

## What to check
- Are all direct **and transitive** dependencies pinned to exact, immutable versions, with a committed lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `requirements.txt` with `==`, `go.sum`, `Gemfile.lock`, `composer.lock`)?
- Does the project enforce reproducible installs (`npm ci`, `pip install -r`, `poetry install --no-cache`, `go mod verify`, `bundle install --deployment`, `composer install --no-dev`) rather than re-resolving ranges?
- Are version ranges (`^`, `~`, `>=`, `*`, `latest`) used for production dependencies instead of exact versions?
- Is there an automated SCA scan (npm audit / `pnpm audit`, `pip-audit`, `safety`, OWASP Dependency-Check, Trivy, Snyk, GitHub Dependabot, `govulncheck`, `bundler-audit`) wired into CI and failing the build on High/Critical CVEs?
- Do any dependencies ship lifecycle scripts (`preinstall`, `postinstall`, `install`, `prepare`) — is the install-time attack surface reviewed? Is `npm install --ignore-scripts` enforced in CI?
- Are private/internal registries configured with authentication, and are registry responses signed or mirrored from an allow-listed upstream?
- Are CDN-hosted third-party scripts (`<script src=...>`, CSS, fonts) loaded with an `integrity=` SRI attribute and `crossorigin`? Are they served over HTTPS from a trusted origin?
- Is an SBOM (CycloneDX, SPDX) generated and stored with each release for traceability?
- Are deprecated/abandoned packages, or packages with very few maintainers / recent maintainer changes (potential hijack), flagged for replacement?

## Static signals
Loose version ranges (supply-chain drift / latent-CVE risk):
- Node: `"lodash": "^4.0.0"`, `"react": "~18.2.0"`, `"foo": "*"` or `"latest"` in `package.json`
- Python: `requests>=2.0` (bare `>=`), `flask` (no version) in `requirements.txt`; Poetry `^`/`~` caret ranges
- Java/Maven: `<version>[1.0,2.0)</version>` (range) in `pom.xml`; Gradle `+` / `latest.release`
- Go: no `go.sum` entry, or `go.mod` with a pseudo-version that is not what CI installs
- Ruby: `gem 'rails'` (no version) or `gem 'rails', '>= 6.0'` in `Gemfile`
- PHP: `"laravel/framework": "^10.0"` or `"vendor/pkg": "dev-master"` in `composer.json`

Missing / uncommitted lockfile:
- `package.json` present but no `package-lock.json`/`yarn.lock` in the repo
- `requirements.txt` without a generated hash (`--require-hashes`) or no `Pipfile.lock`/`poetry.lock`
- `composer.lock` gitignored; `go.sum` missing; `Gemfile.lock` missing

Lifecycle-script supply-chain surface:
- `package.json` with `"scripts": { "postinstall": "...", "preinstall": "...", "install": "...", "prepare": "..." }` — review whether they fetch/execute remote code
- `.npmrc` without `ignore-scripts=true` in CI; install logs showing curl-to-bash during build

Unverified CDN / external asset fetch:
- `<script src="https://cdn.example.com/lib.min.js"></script>` with no `integrity=`/`crossorigin` attribute
- Dockerfile / build script: `curl https://get.example.com/install.sh | sh` with no checksum verification
- `RUN wget -qO- https://... | sh` ; `pip install https://github.com/.../pkg.zip` (VCS/URL install, no hash)

Typosquat / suspicious-dependency indicators:
- package names that are near-misses of popular ones (`reqests`, `crossenv`, `lodash-es-tiny`, `python-dateutil2`)
- dependencies added in the last commit by an unfamiliar contributor with wide blast radius

## False positives
- A committed lockfile exists, installs are reproducible (`npm ci`/`pip install` with hashes/`go mod verify`), and SCA passes — the "range in manifest" is harmless because the lockfile pins the resolved version. Confirm CI actually uses the lockfile.
- The dependency is hosted on an internal, authenticated private registry with a pinned digest and mirrored artifacts — supply-chain risk is reduced to insider trust.
- `latest`/ranges are confined to `devDependencies` and never ship to production builds (verify the production bundle excludes them).
- A CDN script is self-hosted (same origin) or loaded with a valid `integrity` hash and `crossorigin` from a reputable CDN — SRI is present, so MITM swap is detected.
- The CVE is flagged but the vulnerable code path is provably unreachable in this application (document the justification; prefer upgrading regardless).

## Attack scenario
1. Attacker compromises a widely-used upstream package (e.g., maintainer account takeover, or publishes a typosquatted name) and pushes a malicious new minor/patch version.
2. Because the victim app declares `"dep": "^1.2.0"` and has no enforced lockfile (or runs `npm install` instead of `npm ci`), CI pulls the new version on the next build.
3. The malicious version's `postinstall` script exfiltrates environment variables, AWS keys, or `~/.npmrc` tokens to an attacker-controlled server, and/or patches the build to inject a backdoor into the production artifact.
4. Separately, the deployed page loads a CDN script without SRI; an attacker who compromises the CDN (or a malicious upstream maintainer who republishes the file) swaps in a credential-stealing script that runs in every visitor's browser.
5. The attacker pivots from stolen secrets/backdoors to full environment compromise — data exfiltration, lateral movement, ransomware.

## Impact
- **Confidentiality**: stolen secrets, tokens, and source via install-time scripts; leaked user data via backdoored runtime.
- **Integrity**: malicious code executes with full application privileges at build or runtime — backdoors, altered business logic, fraudulent transactions.
- **Availability**: malicious dependencies can brick builds, delete data, or hold the artifact pipeline hostage (e.g., the `event-stream` / `ua-parser-js` / `colors.js` sabotage incidents).
- Severity scales with the dependency's reach: a compromised widely-imported package (transitive blast radius) or a build-time script (full CI/CD takeover) is Critical; an isolated dev-only tool with a known-but-unreachable CVE is Low.

## Remediation
Pin exact versions, commit the lockfile, install reproducibly, and verify integrity:
```jsonc
// VULNERABLE — floating range, no lockfile guarantee, install resolves latest
"dependencies": { "lodash": "^4.0.0", "axios": "*" }

// SAFER — exact pin (lockfile still required for transitive resolution)
"dependencies": { "lodash": "4.17.21", "axios": "1.6.2" }
```
```html
<!-- VULNERABLE — CDN script without integrity -->
<script src="https://cdn.example.com/lib.min.js"></script>

<!-- SAFER — Subresource Integrity pins the hash -->
<script src="https://cdn.example.com/lib.min.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"></script>
```
Defense-in-depth: enforce `npm ci` / `--ignore-scripts` in CI, run SCA (`npm audit`/`pip-audit`/Trivy/Dependabot) as a build gate, use a private mirrored registry with allow-listing, generate an SBOM per release, and apply SRI + a strict CSP (`script-src 'self'` with nonces) for any third-party scripts.

## References
- OWASP ASVS V10.x — Architecture: Malicious Code / Business Logic / Integrity controls (V10.1, V14.1 for components)
- OWASP WSTG-INFO-08 / WSTG-INFO-09 — Fingerprinting / Reviewing Application Architecture & dependencies
- OWASP Cheat Sheets: Dependency Management (with Vulnerable & Outdated Components), Third Party JavaScript Management
- OWASP Top 10 2021 — A06 Vulnerable and Outdated Components; A08 Software and Data Integrity Failures
