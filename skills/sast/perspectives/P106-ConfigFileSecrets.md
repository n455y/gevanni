---
id: P106
name: ConfigFileSecrets
area: V13 Configuration
refs: ASVS V14.x / WSTG-CONF-04 / CS: Secrets Management
requires: [backend]
---

# P106 — ConfigFileSecrets

## Overview
Configuration files, environment files, and container/infrastructure definitions frequently hardcode live secrets in plaintext — database passwords, API keys, JWT signing keys, cloud provider credentials, and service-account tokens. Once committed, these secrets propagate into the source repository history, CI logs, built container images, and downstream artifacts, making rotation and revocation extremely difficult. The root cause is almost always convenience: a developer copies a working value into `.env`, `config/production.yaml`, or a `Dockerfile` `ENV` directive to make the app run, then forgets to externalize it before committing. This perspective is the configuration-layer sibling of P52-HardcodedKeys (which targets secrets embedded directly in source code).

## What to check
- Are real (non-placeholder) secrets present in tracked config files — `config/production.yml`, `application-prod.properties`, `settings.json`, `.env`, `.env.production`?
- Is `.env` (and `*.env.local`, `.env.*.local`) actually gitignored, or is a real `.env` tracked in the repo?
- Are private keys committed — `id_rsa`, `id_ed25519`, `*.pem`, `*.p12`, `service-account.json`, `.npmrc`, `.pypirc`, `.netrc`, `.aws/credentials`?
- Are secrets baked into container images via `Dockerfile` `ENV SECRET=...`, `ARG`, or `COPY .env`? (`docker history` / image layer inspection should reveal nothing.)
- Are sample/template values (e.g. `stripe_secret: sk_live_xxxx`) in fact real, discoverable live credentials rather than documentation placeholders?
- Do infrastructure-as-code files (`docker-compose.yml`, `terraform/*.tf`, Helm `values.yaml`, Kubernetes manifests) embed passwords in plaintext rather than referencing a secret store (`${VAR}`, `secretRef`, `valueFrom`)?
- Does the build emit secrets into CI logs (echoed env vars, debug `print(config)`, `set -x` on a line referencing secrets)?
- Is the git history clean, or were secrets committed and only later "removed" from the working tree (still recoverable via `git log -p` / `git rev-list`)?

## Static signals
Plaintext secrets in config files:
- `config/production.yaml`: `database_password: S3cr3t!`, `stripe_secret: sk_live_...`
- `.env` / `.env.production`: `AWS_SECRET_ACCESS_KEY=...`, `JWT_SECRET=...`, `DATABASE_URL=postgres://user:pass@...`
- `application.yml` / `application-prod.properties` (Java/Spring): `spring.datasource.password=...`
- `settings.py` (Django): `SECRET_KEY = '...'`, `EMAIL_HOST_PASSWORD = '...'`
- `wp-config.php`: `define('DB_PASSWORD', '...');`

Committed credential artifacts:
- `id_rsa`, `id_ed25519`, `*.pem`, `*.p12`, `*.key`, `service-account.json`, `credentials.json`
- `.npmrc` (`_authToken=...`), `.pypirc`, `.netrc`, `.aws/credentials`, `.docker/config.json` (with `auth` base64)

Secrets baked into container/build definitions:
- `Dockerfile`: `ENV DATABASE_PASSWORD=hunter2`, `ARG GITHUB_TOKEN=ghp_...`, `COPY .env /app/.env`
- `docker-compose.yml`: `environment: - POSTGRES_PASSWORD=...`, `MYSQL_ROOT_PASSWORD: ...`

IaC with embedded secrets:
- Terraform: `provider "aws" { secret_key = "..." }`; Helm `values.yaml`: `password: "..."` instead of `existingSecret`
- Kubernetes manifest: `env: [{ name: API_KEY, value: "live-key" }]` instead of `valueFrom: { secretKeyRef: ... }`

Live-looking secret patterns (high-signal regex anchors):
- `sk_live_[0-9a-zA-Z]{24,}` (Stripe live), `gh[pousr]_[0-9a-zA-Z]{36,}` (GitHub tokens), `AKIA[0-9A-Z]{16}` (AWS access key), `xox[baprs]-[0-9a-zA-Z-]+` (Slack), `eyJ[a-zA-Z0-9_-]+\.eyJ` (JWT), `-----BEGIN (RSA |EC )?PRIVATE KEY-----`

## False positives
- The value is a placeholder/example used in documentation or a sample config and is not valid against any real system (`sk_live_xxxx`, `changeme`, `your-key-here`). Confirm by checking the key length/format and whether it appears in CI/runtime.
- Secrets are externalized via a Secret Manager / KMS / Vault and the repo only holds references (`${STRIPE_SECRET}`, `secretRef`, `arn:aws:secretsmanager:...`), injected at runtime — and the repo/image contain no plaintext. This is the desired state.
- A secret-scanning pre-commit/CI hook (gitleaks, trufflehog, detect-secrets) plus repo-pushing protections are in place, reducing the likelihood that a leak persists.
- The committed key is intentionally public (e.g. a public key, a callback URL, an OAuth client *ID* as opposed to secret) — verify the corresponding private/secret half is absent.
- Private key files are present in a *non-tracked* test fixture directory and were never staged.

## Attack scenario
1. An attacker gains read access to the repository (insider, leaked token, third-party contractor, or a public repo accidentally made public).
2. They harvest `config/production.yml`, `.env`, or `service-account.json` containing a live `AWS_SECRET_ACCESS_KEY` and Stripe `sk_live_` key.
3. Even if the file is deleted in the latest commit, the attacker runs `git log --all -p -- '*.env'` and recovers the secret from history.
4. The AWS credentials grant IAM access — they spin up crypto-mining instances or enumerate S3 for customer data. The Stripe key lets them issue refunds/charges. Because the secret is shared across environments, full rotation is required before access is cut off.

## Impact
- **Confidentiality**: full disclosure of credentials — database dumps, customer PII, object-storage contents, third-party API abuse.
- **Integrity**: an attacker holding the DB password or signing key can modify records, mint forged JWTs, or impersonate services.
- **Availability**: cloud credential theft commonly leads to resource hijacking and account suspension (e.g. crypto-mining triggering a provider lockout).
- Severity scales with the privilege of the leaked credential: a production DB root password or a cloud root key is a critical, organization-wide compromise. Secrets in git history remain exploitable until rotated, even after removal from the working tree.

## Remediation
Never commit real secrets; reference an external secret store and inject at runtime:
```yaml
# VULNERABLE — plaintext secret committed to the repo
# config/production.yaml
stripe_secret: sk_live_abcDEF1234567890xyz...
database_url: postgres://app:s3cr3tP@db.internal:5432/prod

# SAFE — external reference resolved from a Secret Manager / KMS / Vault at runtime
# config/production.yaml
stripe_secret: ${STRIPE_SECRET}        # injected via AWS Secrets Manager / GCP Secret Manager
database_url: ${DATABASE_URL}
```
Defense-in-depth: add a secret-scanning hook (gitleaks/trufflehog) in pre-commit and CI, keep `.gitignore` covering `.env*` and credential files, never `COPY` secret files into images (use runtime `valueFrom`/`secretRef`), and treat any committed secret as compromised — rotate it immediately and scrub git history with `git filter-repo`/BFG (noting that clones/forks may retain it).

## References
- ASVS V14.x
- WSTG-CONF-04
- CS: Secrets Management
