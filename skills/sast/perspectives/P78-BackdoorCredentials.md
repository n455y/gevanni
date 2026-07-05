---
id: P78
name: BackdoorCredentials
refs: ASVS V10.x / WSTG-ATHN-02 / CS: Secrets Management, Password Storage
requires: []
---

# P78 — BackdoorCredentials

## Overview
Backdoor credentials are hardcoded login bypasses, master passwords, or magic tokens embedded directly in source code. Unlike properly managed secrets (rotated via a vault/KMS), these are static, often intentionally hidden, and grant privileged access — sometimes deliberately inserted by a malicious insider (supply-chain compromise), sometimes a "temporary" debugging shortcut that shipped to production. They undermine every authentication control: any holder of the source (or a reverse-engineer of the binary) becomes an instant admin, with no audit trail tying them to a real identity. The root cause is always the same: an access decision is made by comparing request input to a literal embedded in the codebase rather than by going through the real identity provider / role framework.

## What to check
- Does any authentication or authorization check compare request input against a **hardcoded constant** — magic header value, query param, master password, or PIN?
- Is there a fixed admin/support account (`admin/admin`, `support:LetMeIn!`) whose credentials live in source, config, or seed/migration files?
- Are webhook, health-check, or internal-API endpoints guarded only by a shared secret committed to the repo (`X-Webhook-Secret: s3cret`)?
- Do comments, commit history, or `.env.example` files contain **real** credentials (not placeholders)? Is a real API key / DB URL present in committed config?
- Are there time-based or IP-based bypasses that disable auth (e.g. `if (Date.now() < maintenanceWindow) return next()`)?
- Does the CI/CD pipeline inject secrets, or are they baked into the Docker image / serverless bundle?
- Are bypass tokens exposed in a public artifact (client-side JS, mobile app binary, Terraform state)?

## Static signals
Hardcoded magic bypass values:
- `if (req.headers['x-magic'] === 'opensesame') return adminPanel();`
- `if (req.body.code === 'letmein123') loginAsAdmin();`
- `if (req.query.token === 'master2024') next();`

Fixed admin/support credentials:
- `const ADMIN_USER = 'admin', ADMIN_PASS = 'backdoor';`
- Python: `if user == 'support' and pwd == 'P@ssw0rd':`
- Java: `if ("root".equals(u) && "toor".equals(p))`
- Go: `if u == "admin" && p == "changeme" {`
- PHP: `if ($_POST['user'] === 'admin' && $_POST['pass'] === 'admin123')`
- Ruby: `if params[:user] == 'admin' && params[:pass] == 'secret'`

Hardcoded shared secrets for webhooks / internal APIs:
- `const WEBHOOK_SECRET = 'whsec_abc123';`
- `verifySignature(req, 'shared-secret-prod');`
- Django settings: `WEBHOOK_SECRET = 'supersecret'`

Real credentials in committed config / comments:
- `.env`: `DATABASE_URL=postgres://prod:Hunter2@db.internal/app` (not a placeholder)
- `# TODO remove: AWS_SECRET_ACCESS_KEY = wJalrXUt...`
- `config.yaml`: `stripe_secret: sk_live_51...`
- `.env.example` with a real-looking (non-placeholder) value

Hardcoded JWT signing keys / API tokens:
- `const JWT_SECRET = 'supersecret';`
- `API_TOKEN = 'ghp_xxxxxxxxxxxx';`

## False positives
- All secrets are loaded from a managed secret store (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, Doppler) at runtime and only a **reference / ARN** is committed. Confirm the literal is truly absent from the repo.
- The "credential" is a **non-secret public value** (publishable API key like `pk_live_`, app ID, feature-flag client key) intentionally exposed client-side — not an auth bypass.
- The matched string is a placeholder in documentation (`YOUR_API_KEY_HERE`, `<password>`, `changeme` in a template with no real value behind it).
- A test fixture uses obviously fake values (`test-user`/`test-pass`) and is excluded from the production build / image — but still flag if the test path is reachable in a shipped artifact.
- A magic value gates a **non-sensitive** action (e.g. a feature toggle query param that only changes UI) with no privilege escalation.

## Attack scenario
1. Attacker obtains the source — leaked repo, public fork, decompiled mobile app, or exposed Terraform state — and finds `if (req.headers['x-support'] === 'godmode') return grantAdmin();`.
2. Attacker sends a single request: `curl -H 'x-support: godmode' https://app.example.com/admin/users`.
3. The hardcoded comparison passes; the handler issues an admin session or returns the user table — no real login, no MFA, no rate limit.
4. Because the value is static, the attacker can reuse it indefinitely and from any IP. If the same secret is deployed across environments/instances, one leak compromises the whole fleet.
5. Audit logs show "anonymous" or no user, leaving no attribution; the backdoor persists silently until someone rotates it (which, being hardcoded, requires a redeploy).

## Impact
- **Confidentiality**: full read of all user data, secrets, and PII via the privileged account.
- **Integrity**: arbitrary data modification, account creation, privilege grants, persistence planting.
- **Availability**: account deletion, config wipe, ransom / data destruction.
- Severity is **Critical** when the credential grants admin or when it bypasses MFA. A static secret in a public artifact (client-side bundle, mobile app) is effectively a 0-day waiting to be used — anyone can find it, and it cannot be revoked without a redeploy.

## Remediation
Route every access decision through the real identity/role framework; never compare against a hardcoded literal:
```ts
// VULNERABLE — hardcoded magic bypass
app.get('/admin', (req, res) => {
  if (req.headers['x-magic'] === 'opensesame') return adminPanel();
  res.redirect('/login');
});

// SAFE — real auth + role check + audit
app.get('/admin',
  authenticate,
  requireRole('admin'),
  audit('admin.access'),
  handler,
);
```
Store all secrets in a managed vault (Vault / Secrets Manager / KMS) and inject them at runtime via env vars — never commit literals. Run a secret-scanning tool (gitleaks, trufflehog) in CI to block hardcoded credentials before merge, and add defense-in-depth monitoring (alert on any login that skipped MFA or matched a known-bypass signature).

## References
- OWASP ASVS V10.x — Malicious code and unauthorized access (hardcoded credentials, backdoors)
- OWASP WSTG-ATHN-02 — Testing for bypassing authentication schema (default/hidden credentials)
- OWASP Cheat Sheets: Secrets Management, Password Storage, Authentication
