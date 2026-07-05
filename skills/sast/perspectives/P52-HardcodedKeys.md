---
id: P52
name: HardcodedKeys
refs: ASVS V6.2.x, V14 / WSTG-CONF-04, WSTG-CRYP-04 / CS: Cryptographic Storage, Secrets Management
requires: [backend]
---

# P52 — Hardcoded Keys & Secrets

## Overview
Hardcoded secrets are cryptographic keys, JWT signing keys, API tokens, database passwords, or cloud credentials committed directly into source code, configuration files, or container images — instead of being injected at runtime from a secret manager or environment variable. The root cause is almost always convenience: a developer hardcodes a value to make the app start, then forgets to externalize it. Because source code is shared across environments (dev/test/prod), version-controlled indefinitely, cloned to developer laptops, and increasingly mined by attackers who scan public repos and leaked images, a single committed secret effectively grants its privilege to everyone with read access — and to anyone who later obtains the git history. Once a secret is in git, rotating it is mandatory: git history is immutable, so "deleting" the line does not retract the leaked value.

## What to check
- Are any cryptographic keys (AES, HMAC, RSA/EC private keys), JWT signing secrets, session-encryption keys, or password-hash peppers assigned from string literals in source?
- Are API keys, service-account JSON, cloud access keys (AWS `AKIA…`, GCP, Azure), SMTP credentials, or third-party tokens (`sk_live_`, `ghp_`, `xoxb-`, `AIza…`) embedded in code, `.env`, `config.yml`, `application.properties`, `settings.py`, or committed Docker images?
- Do database connection strings contain inline passwords (`postgres://user:pass@host`) that are hardcoded rather than composed from injected env vars?
- Is there a fallback default when an env var is unset (`process.env.KEY || 'devkey'`, `os.getenv('KEY', 'changeme')`) that ships to production when the var is absent?
- Are `.env`, `.env.local`, `secrets.json`, `*.pem`, `*.p12`, or service-account keys present in the repo — and is `.gitignore` actually excluding them?
- Are secrets passed via build args (`docker build --build-arg SECRET=…`) that end up in image layer metadata and `docker history`?
- Is the secret rotated, and is rotation logged? Static secrets that "never change" indicate manual/embedded handling.
- For private keys: is the corresponding public key hardcoded for signature verification (legitimate), or is a *private* key embedded for signing/decryption (vulnerable)?

## Static signals
Hardcoded literal assignments:
- Node/JS: `const JWT_SECRET = 'supersecret'`, `const KEY = 'changeme'`, `const stripe = Stripe('sk_live_...')`
- Python: `SECRET_KEY = 'django-insecure-...'`, `app.config['SECRET_KEY'] = 'dev'`, `API_KEY = "ghp_xxx"`
- Java: `private static final String SECRET = "password";`, `SecretKeySpec("1234567890123456".getBytes(), "AES")`
- Go: `var signingKey = []byte("secret")`, `const APIKey = "AKIA..."`
- PHP: `$db_pass = 's3cret';`, `define('JWT_SECRET', 'secret');`
- Ruby: `SECRET_KEY_BASE = '...'`, `Rails.application.secrets` populated from a committed `secrets.yml`

Weak/insecure fallback defaults:
- `process.env.JWT_SECRET || 'devkey'`
- `os.environ.get('SECRET_KEY', 'changeme')`
- `System.getenv("DB_PASSWORD") != null ? ... : "admin"`
- `viper.SetDefault("jwt_secret", "secret")`

Inline credentials in connection strings / URLs:
- `mongodb://admin:p@ssw0rd@cluster/`, `postgres://user:pass@host:5432/db`
- `https://user:pass@api.example.com`, `redis://:password@host:6379`

Committed secret-bearing files (check `.gitignore` + `git log`):
- `.env`, `.env.production`, `secrets.json`, `config/credentials.yml.enc` (without key), `*.pem`, `*.key`, `*.p12`, `serviceaccount.json`, `id_rsa`

Build-arg secret leakage:
- `docker build --build-arg AWS_ACCESS_KEY_ID=...` (visible in `docker history`)
- `ENV DB_PASSWORD=secret` in a `Dockerfile`

Recognizable token formats worth grepping:
- AWS: `AKIA[0-9A-Z]{16}`, `aws_secret_access_key`
- Stripe: `sk_live_[0-9a-zA-Z]{24,}`, `rk_live_`
- GitHub: `gh[pousr]_[A-Za-z0-9]{36}`
- Slack: `xox[baprs]-[0-9A-Za-z-]{10,}`
- Google API: `AIza[0-9A-Za-z_\-]{35}`
- Generic JWT: `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.`

## False positives
- The value is fetched from a secret manager / KMS / Vault / AWS Secrets Manager / Spring Cloud Config at startup, and the app **refuses to boot** when it is absent (fails closed) — confirm there is no insecure fallback.
- A *public* key or certificate is hardcoded solely for signature/JWT verification — public keys are not secret by definition.
- The literal is a non-secret constant: an IV/nonce is fine to store alongside ciphertext, a PBKDF2 salt is fine to store, a key *ID* (`kid`) is not the key.
- Test fixtures use clearly fake/mocked values (`test_key_123`, mocked client) and never connect to production — verify test secrets differ from prod and are not reused.
- The "secret" is a placeholder inside a config template (`config.example.yml`) that documents the shape without containing a real value.
- The repo is a sandbox with throwaway credentials never used outside it (still flag if the pattern could be copy-pasted into real code).

## Attack scenario
1. Attacker scans public GitHub / GitLab with tools like `truffleHog`, `gitleaks`, or regex over commit history, and finds a committed `JWT_SECRET` or AWS `AKIA…` key from 18 months ago.
2. The secret is still live because it was never rotated (git history is immutable; deleting the line did nothing).
3. For a JWT signing key: the attacker mints forged tokens for any user (e.g., `admin`), authenticating as them without a password — full account takeover.
4. For an AWS/cloud key: the attacker spins up crypto-mining instances, exfiltrates S3 buckets, or pivots into the production VPC — direct infrastructure compromise and likely large cost/audit fallout.
5. For a DB password: the attacker connects from a reachable network path and dumps user data — mass PII breach.

## Impact
- **Confidentiality**: decryption of all data protected by the key (tokens, sessions, backups, TLS-termination traffic); full DB/credential disclosure.
- **Integrity**: forged JWTs/authentication, unauthorized writes, code-signed malware if a signing key leaks.
- **Availability**: cloud-key compromise can lead to resource deletion, ransom, or quota exhaustion that takes the service down.
- Severity scales steeply with the secret's scope: a per-user token affects one account; a global JWT signing key, DB root password, or cloud root credential can compromise the entire system and is typically rated Critical (CVSS 9.0+).

## Remediation
Load every secret from an external source at startup and fail closed if missing:
```ts
// VULNERABLE — hardcoded secret + insecure fallback
const KEY = 'supersecret';
const token = jwt.sign(payload, 'secret');
const stripe = Stripe('sk_live_abc123');

// SAFE — injected, validated, fails closed
const KEY = process.env.SIGNING_KEY;
if (!KEY) throw new Error('SIGNING_KEY is required');
const token = jwt.sign(payload, KEY, { algorithm: 'HS256' });
```
```python
# VULNERABLE
SECRET_KEY = 'django-insecure-hardcoded'
API_KEY = os.getenv('API_KEY', 'changeme')   # silent fallback

# SAFE
SECRET_KEY = os.environ['SECRET_KEY']        # KeyError if missing → app won't boot
```
As defense-in-depth: store secrets in a manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault), rotate them regularly, inject them as runtime env vars (never as Docker `--build-arg`), add a pre-commit secret scanner (`gitleaks`/`truffleHog`), and immediately rotate any secret found in git history — removing the line does not retract the leaked value.

## References
- ASVS V6.2.x, V14
- WSTG-CONF-04, WSTG-CRYP-04
- CS: Cryptographic Storage, Secrets Management
