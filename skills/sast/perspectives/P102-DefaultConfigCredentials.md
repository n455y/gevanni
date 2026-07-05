---
id: P102
name: DefaultConfigCredentials
refs: ASVS V14.x / WSTG-CONF-04 / CS: Default Passwords, Authentication
requires: [backend]
---

# P102 — DefaultConfigCredentials

## Overview
Default or weak credentials baked into configuration layers — database servers, caches (Redis/Memcached), message brokers, admin consoles, container base images, and infrastructure service accounts — remain a top cause of rapid system compromise. Unlike application-level user accounts (see P15), these are the **configuration-layer secrets** that the application relies on at boot: a `postgres/postgres` DB login, an unauthenticated `redis://redis:6379`, a sample `config.json` shipped to production verbatim. The root cause is usually copy-pasted sample values, hardcoded defaults in base images or Helm charts, or secrets committed to VCS rather than injected from a secrets manager. Because these services are often trusted and least-privilege is rarely enforced, one unchanged default frequently leads to full data exfiltration or remote code execution.

## What to check
- Are any **database / cache / broker / search-engine** connection strings carrying literal usernames and passwords instead of environment variables or secret references (`${DB_PASSWORD}`, Vault, AWS Secrets Manager, Kubernetes Secrets)?
- Do defaults match well-known pairs: `postgres/postgres`, `root:` (empty), `admin/admin`, `sa/sa`, `redis` with no `AUTH`, `mongo` no-auth, `rabbitmq`/`guest:guest`, `elasticsearch` no-auth?
- Are sample/seed config files (`config.sample.json`, `.env.example`, `docker-compose.yml`, Helm `values.yaml`) deployed to production with their placeholder values unchanged?
- Is the **Redis/Memcached** instance bound on `0.0.0.0` with no password (`requirepass` unset)? Same for Elasticsearch (`xpack.security.enabled: false`), MongoDB (`--auth` missing), and Kafka?
- Do admin consoles (Tomcat manager, Jenkins, Grafana, Jenkins default `admin/admin`, Spring Boot Actuator endpoints without auth) ship with unchanged credentials or no auth?
- Are container base images (`mysql:5.7` with `MYSQL_ROOT_PASSWORD=root`, `rabbitmq` default guest) instantiated without a password override?
- Are secrets committed to git history (`.env`, `application.properties`, `secrets.yml`, `config/credentials.yml.enc` key)? Check for the file **and** for prior commits.
- Is least-privilege violated — does the app connect as `root`/`sa`/superuser rather than a scoped role?
- Are service-account tokens / cloud keys (`AWS_ACCESS_KEY_ID`, GCP service-account JSON) hardcoded in config or CI scripts?

## Static signals
Hardcoded credentials in config / code:
- JS/TS: `db: { user: 'root', pass: '' }`, `password: 'postgres'`, `redis://redis:6379` (no auth), `REDIS_URL=redis://localhost`
- Python: `DATABASE_URL = 'postgresql://postgres:postgres@db:5432/app'`, `app.config['SQLALCHEMY_DATABASE_URI']`
- Java: `spring.datasource.password=admin`, `spring.data.redis.password=`(empty), `management.security.enabled=false`
- Go: `const dbPass = "postgres"`, `dsn := "root:@tcp(db:3306)/app"`
- PHP: `'password' => env('DB_PASSWORD', 'secret')` (weak fallback), Laravel `.env` `DB_PASSWORD=`
- Ruby: `Rails.application.config.database = { password: 'postgres' }`, `Sidekiq.configure_server { |c| c.redis = { url: 'redis://redis:6379' } }`

Sample values shipped as real config:
- `.env.example` / `config.sample.json` / `values.yaml` values identical to the deployed `.env` / configmap
- `docker-compose.yml` with `MYSQL_ROOT_PASSWORD: root`, `POSTGRES_PASSWORD: postgres`, `RABBITMQ_DEFAULT_USER/PASS: guest`
- Seed/migration scripts: `CREATE USER 'app' IDENTIFIED BY 'admin';`

No-auth / insecure service defaults:
- Redis: `# requirepass foobared` (commented out), `bind 0.0.0.0`, `protected-mode no`
- Elasticsearch: `xpack.security.enabled: false`
- MongoDB: connection string without `?authSource=admin` and no user; `--noauth`
- Spring Boot Actuator: `management.endpoints.web.exposure.include: *` with no security

Cloud / CI hardcoded secrets:
- `AWS_ACCESS_KEY_ID=AKIA...`, `AWS_SECRET_ACCESS_KEY=...` in `.env` or `.github/workflows/*.yml`
- GCP service-account JSON inlined in a script; Slack/webhook tokens in config

## False positives
- The literal in the repo is the **sample/template** (`.env.example`) and production injects real values from a secrets manager at runtime — verify the deployed config, not just the template.
- Local dev defaults (`postgres`/`postgres` on `localhost`) are acceptable **only if** production overrides them and dev cannot reach prod resources.
- The service is bound to `127.0.0.1` / a private network with strict firewall rules and the value is a strong rotated secret, not a default — defense-in-depth still wants auth, but severity drops.
- A value that *looks* like a default (e.g. `admin`) but is actually a strong random secret mislabeled — confirm length/entropy before flagging.
- Honeypot / intentionally-open services clearly documented as such.

## Attack scenario
1. Attacker enumerates the target's exposed services (Shodan, nmap) and finds a Redis on `0.0.0.0:6379` with no `AUTH` — a default left from the sample compose file.
2. With unauthenticated Redis access, the attacker writes their SSH public key (`config set dir /root/.ssh; set ssh_key ...; save`) or a cron job achieving RCE.
3. Alternatively, the attacker finds the source repo, reads `docker-compose.yml`, and obtains the `MYSQL_ROOT_PASSWORD: root`; if MySQL is reachable (or via SSRF/SQLi escalation), they dump every table.
4. Default Jenkins/Grafana/Tomcat-manager credentials grant admin console access, leading to code execution (script consoles, WAR deploy) and lateral movement across the internal network.

## Impact
- **Confidentiality**: full DB/cache dump, secret/key exfiltration, PII exposure.
- **Integrity**: data tampering/deletion, backdoor accounts, malicious config injection, supply-chain poisoning via build tools.
- **Availability**: ransomware-style encryption (`FLUSHALL`, `DROP TABLE`), service wipe.
- Severity scales with the privilege of the default account (superuser/`root`/cluster admin = catastrophic) and the reachability of the service (internet-facing vs internal-only). Internet-reachable defaults routinely lead to full environment takeover within minutes of disclosure.

## Remediation
Never commit real secrets; inject them from a secrets manager and rotate any default on first boot:
```yaml
# VULNERABLE — default / weak values shipped to production
db:
  user: postgres
  password: postgres          # unchanged default
redis:
  url: redis://redis:6379      # no auth, exposed

# SAFE — injected, strong, least-privilege
db:
  user: ${DB_USER}             # scoped role, not superuser
  password: ${DB_PASSWORD}     # strong random, from Vault/Secrets Manager
redis:
  url: redis://:${REDIS_PASSWORD}@redis:6379   # AUTH enabled
```
Force password rotation for any base image on startup (`MYSQL_ROOT_PASSWORD` from a generated secret, `MYSQL_RANDOM_ROOT_PASSWORD=1`), enforce `requirepass` + `protected-mode yes` on Redis, enable `xpack.security` on Elasticsearch, and scan the repo/secrets manager with `gitleaks`/`trufflehog` plus a CI check that rejects known defaults (e.g. the SecLists default-credentials dictionary) as defense-in-depth.

## References
- ASVS V14.x
- WSTG-CONF-04
- CS: Default Passwords, Authentication
