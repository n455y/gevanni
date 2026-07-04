---
id: P71
name: TLSEnforcement
area: V12 Secure Communication
refs: ASVS V9.1.x / WSTG-CRYP-03 / CS: Transport Layer Protection Cheat Sheet
---

# P71 — TLS Enforcement

## Overview
TLS enforcement is the discipline of guaranteeing that **every hop** carrying sensitive data — edge to load balancer, LB to application, app to database/cache/queue, service to service — is encrypted, authenticated, and pinned to modern protocols. The defect class is broader than "no HTTPS": it includes plaintext fallback, protocol/cipher downgrade, disabled certificate verification, expired/pin-drifted certificates, and a TLS-terminating edge that hands traffic to the app over cleartext on the internal network. Root causes are usually misconfigured defaults (`http.listen(80)` with no redirect), dev conveniences leaked to prod (`rejectUnauthorized: false`, `verify=none` in Postgres), or an assumption that "the VPC is trusted" so internal links need no TLS. The consequences — credential/session sniffing, MITM alteration of responses, and stripped-to-HTTP redirects — are severe precisely because the outer TLS often hides an insecure interior.

## What to check
- Does the app listen on plaintext HTTP with **no** 301/308 redirect to HTTPS, or accept HTTP after the redirect (no HSTS, redirect chain followable)?
- Is **HSTS** set (`Strict-Transport-Security`) with an adequate `max-age` (>= 6 months, ideally 2 years), `includeSubDomains`, and `preload` for public-facing hosts?
- Are all **outbound** connections — DB, Redis/Memcached, message broker (Kafka/RabbitMQ), SMTP, third-party APIs, cloud SDKs, webhook callbacks — using `tls://`/`amqps`/`ldaps`/`https://`, or plaintext equivalents (`tcp://`, `amqp`, `redis://`, `http://`, `mysql://` without `sslmode`)?
- Is **certificate verification enabled** on every TLS client (`rejectUnauthorized`/`verifyMode: peer`/`checkServerIdentity`)? Any `allowInsecure`, `InsecureSkipVerify`, `verify=none`, `sslmode=disable`/`prefer`, or empty CA bundle is a finding.
- Is the minimum protocol TLS 1.2 (preferably 1.3) with SSLv2/SSLv3/TLS 1.0/1.1 disabled at every listener?
- Are certificate **pins** or **SPKI hashes** used for high-value endpoints, and are they rotated before expiry (no hard failure on pin drift in prod)?
- For internal service-to-service traffic, is **mTLS** enforced (both sides authenticated), or is the mesh relying on network trust alone?
- Does the app set security-relevant cookies with `Secure` (and `HttpOnly`, `SameSite`) so they are never sent over HTTP?
- Are mixed-content resources (`http://` scripts/images/css on an `https://` page) loaded, which browsers may block or downgrade?

## Static signals
Plaintext listeners / no redirect:
- Node: `app.listen(80)`, `http.createServer(...).listen(80)` without an HTTPS redirect
- Python: `app.run(port=80)`, `uvicorn ... --port 80`, Flask `app.run(ssl_context=None)`
- Go: `http.ListenAndServe(":80", mux)` with no TLS listener
- Java: `server.setScheme("http")`, Spring `server.ssl.enabled=false`

Disabled verification (the highest-signal pattern):
- Node: `rejectUnauthorized: false`, `agent: new https.Agent({ rejectUnauthorized: false })`, `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`
- Python: `verify=False` in `requests`, `ssl._create_unverified_context()`, `ssl.CERT_NONE`
- Go: `InsecureSkipVerify: true` in `tls.Config`
- Java: `TrustManager` that does nothing in `checkServerTrusted`, `setHostnameVerifier(ALLOW_ALL)`, `-Dcom.sun.net.ssl.checkRevocation=false`
- PHP: `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false)`, `CURLOPT_SSL_VERIFYHOST = 0`
- Ruby: `OpenSSL::SSL::VERIFY_NONE`, `verify_mode: OpenSSL::SSL::VERIFY_NONE`
- Ruby/Rails: `config.force_ssl = false`

Plaintext internal connections:
- `redis://` instead of `rediss://`; `amqp://` instead of `amqps://`; `ldap://` instead of `ldaps://`
- Postgres: `sslmode=disable` or `sslmode=prefer` (downgrades to plaintext on any error) vs `sslmode=require`/`verify-full`
- MySQL: connection string without `sslmode=REQUIRED` or `requireSSL=true`
- MongoDB: `?ssl=false` or no `tls=true`; `allowInvalidCertificates: true`
- `http://` URLs to internal/private IPs (`http://10.`, `http://169.254.169.254`, `http://localhost:`) for service calls, metadata, or webhooks
- gRPC: `grpc.Dial("...:443", grpc.WithInsecure())` / `grpc.WithTransportCredentials(insecure.NewCredentials())`

Cookie / header gaps:
- `Set-Cookie` without `Secure`
- No `Strict-Transport-Security` header set on HTTPS responses

## False positives
- The app is deployed behind a TLS-terminating reverse proxy (nginx/ALB/Cloudflare) and only the **internal** hop is plaintext on a loopback socket — *acceptable only if* the proxy guarantees TLS on the external side, sets HSTS, and the internal hop never leaves the host/pod. Still flag for hardening.
- A plaintext listener exists solely to issue a `308` permanent redirect to HTTPS (the canonical redirect pattern) — confirm it serves nothing else and sets HSTS on the HTTPS side.
- Local dev uses `http://localhost`; the production config path (env-driven) enables TLS — verify the prod flag, then dismiss.
- A self-signed certificate with verification intentionally relaxed *inside an isolated test harness* that never ships to prod.
- Health-check endpoints (`/healthz`) on a private port that carry no sensitive data and are not internet-exposed.

## Attack scenario
1. The app listens on HTTP:80 with no redirect/HSTS, and an internal DB call uses `sslmode=prefer`.
2. An attacker on the same network (coffee-shop Wi-Fi, hostile cloud tenant, compromised router) ARP-spoofs or BGP-hijacks the victim's traffic.
3. The victim's browser, given no HSTS pin, accepts an HTTP response; the attacker strips the `https://` upgrade and reads session cookies in cleartext.
4. Separately, the attacker MITMs the app-to-DB link: `sslmode=prefer` falls back to plaintext on the attacker's injected TLS error, exposing queries, credentials, and PII.
5. With a stolen admin session cookie the attacker pivots to full account takeover; the plaintext DB traffic also enables response tampering (e.g., returning `is_admin=true`).

## Impact
- **Confidentiality**: full read of session tokens, credentials, PII, and internal API traffic on any plaintext hop.
- **Integrity**: MITM can alter responses (inject scripts, swap download links, forge authorization data) and tamper with DB query results.
- **Availability**: downgrade attacks can force weak ciphers or break connections; pinned-cert mis-rotation can take services offline.
- Severity scales from "information disclosure" (metadata-only plaintext) to "full compromise" when session cookies or DB credentials traverse the cleartext hop. Findings on the authentication/session path are Critical; internal-only plaintext with no secrets is High/Medium depending on data sensitivity.

## Remediation
Terminate TLS at the edge **and** re-encrypt to the app; redirect all HTTP and set HSTS; verify certificates everywhere.
```ts
// VULNERABLE — plaintext listener, no redirect, insecure internal call
app.listen(80);
const db = pg('postgres://db:5432/app?sslmode=disable');
axios.get('http://internal-svc/users', { httpsAgent: new https.Agent({ rejectUnauthorized: false }) });

// SAFE — 308 redirect on :80, HTTPS on :443 with modern opts, HSTS, mTLS/verified internal call
http.createServer((req, res) => res.redirect(308, `https://${req.headers.host}${req.url}`)).listen(80);
https.createServer(tlsOpts, app).listen(443);
app.use((req, res, next) => { res.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload'); next(); });
const db = pg('postgres://db:5432/app?sslmode=verify-full&sslrootcert=/etc/ssl/db-ca.pem');
axios.get('https://internal-svc/users', { ca: fs.readFileSync('/etc/ssl/internal-ca.pem') }); // verify on
```
Defense-in-depth: enforce mTLS between internal services (service mesh / Istio / Linkerd), automate certificate rotation (cert-manager / ACME), continuously monitor for certificate expiry and pin drift, and set `Secure; HttpOnly; SameSite=Lax` on all session cookies so they can never leak over HTTP.

## References
- OWASP ASVS V9.1.x — Communications security (TLS everywhere, HSTS, certificate validation)
- OWASP WSTG-CRYP-03 — Testing for Weak Transport Layer Security
- OWASP Cheat Sheet: Transport Layer Protection Cheat Sheet
