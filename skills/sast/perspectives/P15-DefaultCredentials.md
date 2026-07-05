---
id: P15
name: DefaultCredentials
refs: ASVS V2.x / WSTG-ATHN-02, WSTG-CONF-04 / CS: Authentication, Default Passwords
requires: [backend]
---

# P15 — Default Credentials

## Overview
Default credentials are factory or seeded authentication secrets (`admin/admin`, `admin/password`, `root/root`, vendor defaults, sample seed users) that ship with an application, framework, device, or dependency and are **never removed or forced to change** before the system reaches production. The root cause is almost always operational rather than algorithmic: seed/migration code, infrastructure-as-code, or a vendored admin account is created with a weak or well-known password, and no lifecycle step rotates it or forces a first-login change. Because these passwords are published in vendor manuals, GitHub repositories, and credential-spray dictionaries, leaving them in place is functionally equivalent to leaving an unauthenticated admin console open to anyone who can reach the login form.

## What to check
- Are seeded/bootstrap users (`admin`, `root`, `support`, `system`, `guest`) created in migrations, seed files, fixtures, or IaC with weak or hardcoded passwords (`admin`, `password`, `123456`, `changeme`, `Welcome1`)?
- Does any seeded account have elevated privileges (admin, superuser, full-scope token) but **no forced first-login password change** (`mustChangePassword`, `password_changed_at IS NULL`, `temporary_password`)?
- Are vendor/framework defaults left in place — Tomcat `tomcat/tomcat`, Jenkins `admin/admin`, Grafana `admin/admin`, MongoDB open with no auth, Redis no password, RabbitMQ `guest/guest`, MySQL `root` with empty password, Postgres `postgres` trust auth?
- Are test/demo credentials baked into production builds or container images via `ENV`, build args, or committed `.env` files that ship to prod?
- Is the password-change enforcement bypassable (e.g., the `mustChange` flag is checked client-side only, or a separate API sets it false without rotating the password)?
- Are credentials embedded in infrastructure — Terraform/Kubernetes manifests, Helm values, CI/CD variables, Docker `ENTRYPOINT` scripts — using literal strings instead of a secrets manager?
- Does the application rotate credentials on install/first-run, or are the seeded values the live production passwords indefinitely?

## Static signals
Hardcoded credentials in seed/migration/IaC:
- Node/TypeScript: `User.create({ email:'admin@x', password: hash('admin'), role:'admin' })`, `await db.user.upsert({ password: 'password' })`
- Python/Django: `User.objects.create_superuser('admin', 'admin@x', 'admin')`, `password='changeme'` in `manage.py loaddata` fixtures or `0001_initial` migrations
- Python/Fabric/Ansible: `run('mysql -u root')` with no password, `extra_vars: { db_pass: 'password' }`
- Ruby/Rails: `User.create!(email:'admin@x', password:'password', admin:true)` in `db/seeds.rb`
- Java/Spring: `new User("admin", passwordEncoder.encode("admin"), roles("ADMIN"))` in a `CommandLineRunner` or `data.sql`
- Go: `&User{Name:"admin", Pass: hash("admin")}` in a `main()` bootstrap block
- PHP/Laravel: `DB::table('users')->insert(['email'=>'admin@x','password'=>Hash::make('password')])` in a seeder; WordPress `define('FTP_PASS','admin')`
- Shell/Docker: `ENV MYSQL_ROOT_PASSWORD=root`, `docker run ... -e ADMIN_PASSWORD=admin`
- Terraform/Helm: `password = "admin"`, `--set adminPassword=admin`

Bootstrap admin without forced change:
- Missing `must_change_password`, `password_reset_required`, or `first_login` flag on the seeded row
- Login handler never inspects such a flag before issuing a session token

## False positives
- The seed is gated behind an environment check and only runs in dev/test (`if process.env.NODE_ENV !== 'production'`, fixture loaded only by the test runner, a `data-test` seeder excluded from the prod Docker stage). Confirm there is genuinely no path to production injection.
- The seeded password is a strong, unique, per-deploy random value fetched from a secrets manager / generated at first boot and **rotated immediately**, with `mustChangePassword` enforced server-side.
- A vendored account exists but is disabled by default (`active:false`) and must be explicitly enabled by an operator with a separate credential.
- The "default" is a public, intentionally anonymous read-only account (e.g., a docs site) with no write or admin capability — verify it has no privilege escalation path.

## Attack scenario
1. Attacker enumerates likely defaults: reads the framework's docs/GitHub, checks published default-password lists, or simply tries `admin/admin`.
2. Attacker submits `admin / admin` (or `admin / password`, `root / root`) to the login endpoint — succeeds because the seed account was never rotated.
3. The seeded account holds an admin/superuser role, so the attacker lands directly in the admin console, bypassing the entire authentication threat model.
4. From the admin panel the attacker creates a persistence backdoor account, exports the user database, or pivots to integrated systems (SSO, billing, storage).
5. Because the credentials are shared across every deployment of this app, the same spray succeeds against every unpatched instance worldwide.

## Impact
- **Confidentiality**: full read of user data, secrets, and configuration; total data exfiltration.
- **Integrity**: arbitrary record creation/modification/deletion, backdoor account creation, tampering with audit logs.
- **Availability**: account deletion, destructive migrations, ransomware-style data wipes via admin tooling.
- Severity is **Critical** when the default account is privileged and reachable from the network — default-credential abuse is a routine first step in mass exploitation and ransomware campaigns. It is reduced to Low only when the credential is confined to a non-production, unprivileged, network-isolated context.

## Remediation
Never ship hardcoded credentials; generate per-deploy secrets and force rotation on first login:
```ts
// VULNERABLE — weak seeded admin with no forced change, ships to production
await User.create({ email: 'admin@x.com', password: hash('admin'), role: 'admin' });

// SAFE — strong random temp password from secrets manager + server-side forced change
const tempPassword = await secretsManager.generate(); // high-entropy, per-deploy
await User.create({
  email: process.env.BOOTSTRAP_ADMIN_EMAIL,
  password: hash(tempPassword),
  role: 'admin',
  mustChangePassword: true, // enforced server-side before any session is granted
});
```
Scan seed/migration/IaC for literal passwords in CI (e.g., `gitleaks`, `trufflehog`, `detect-secrets`), disable or remove vendor default accounts on every fresh deployment, and require MFA on all privileged accounts as defense-in-depth.

## References
- OWASP ASVS V2.x — Authentication architectural requirements (no default passwords, forced credential rotation)
- OWASP WSTG-ATHN-02 — Testing for Default Credentials
- OWASP WSTG-CONF-04 — Review Old/Backup/Unreferenced Files and configuration defaults
- OWASP Cheat Sheets: Authentication, Password Storage
