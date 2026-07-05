---
id: P73
name: CertValidationDisabled
refs: ASVS V9.2.x / WSTG-CRYP-03 / CS: TLS Pinning, Transport Layer Protection
requires: []
---

# P73 — CertValidationDisabled

## Overview
TLS certificate validation is the client's defense against man-in-the-middle (MITM) attacks on outbound connections — to upstream APIs, webhooks, databases over TLS, mail servers, or message brokers. Disabling it (`rejectUnauthorized: false`, `verify=False`, `checkServerIdentity` returning nothing, an empty trust manager) makes the channel cryptographically opaque but **not authenticated**: anyone who can intercept traffic (rogue Wi-Fi, BGP hijack, malicious proxy, compromised CA in the bundle) can present any certificate and read or alter the data. The root cause is almost always a debugging shortcut ("the self-signed cert broke staging") that was never reverted before release, or a misguided attempt to "fix" handshake errors. This is a system-wide kill switch: one flag disables authentication for the entire process or connection, silently.

## What to check
- Does any outbound TLS client disable verification? Look for `rejectUnauthorized: false`, `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`, `checkServerIdentity: () => undefined`, `verify=False`/`verify_mode=CERT_NONE`, Go `InsecureSkipVerify: true`.
- Is the disable process-global (`NODE_TLS_REJECT_UNAUTHORIZED=0`, a custom global `https.Agent`, monkey-patching `ssl._create_default_https_context`) rather than scoped to one connection?
- Are hand-rolled trust managers / `X509TrustManager` implementations that return an empty accepted-issues list or never throw on chain errors (Java, .NET `ServerCertificateValidationCallback` returning `true`)?
- Are connection errors swallowed with `try/except`/`catch` and the verification flag flipped as a "fix" rather than diagnosing the cert chain (expired cert, missing intermediate, hostname mismatch, untrusted root)?
- Are self-signed dev certificates still trusted in the production build (bundled CA, `NODE_EXTRA_CA_CERTS` pointing at a dev CA, hosts file overrides)?
- For high-value integrations (payments, identity providers, banking, mTLS partners): is certificate **pinning** layered on top of normal validation, or is the trust store the only gate (any publicly trusted CA can impersonate)?
- Is hostname verification (`verify_hostname`/`checkServerIdentity`) disabled while chain validation remains on? Both must be enforced — a valid chain for the wrong name is still MITM-able.
- Do HTTP clients accept a system-supplied proxy (`HTTP_PROXY`/`HTTPS_PROXY`) without re-validating the upstream cert through the tunnel?

## Static signals
Node.js / JavaScript:
- `https.request({ rejectUnauthorized: false })`, `https.get(url, { rejectUnauthorized: false }, cb)`
- `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` or the same set in a Dockerfile / shell wrapper
- `new https.Agent({ rejectUnauthorized: false })`, `axios`/`got`/`request`/`node-fetch` instantiated with that agent
- `options.checkServerIdentity = () => undefined;` (hostname check neutralized)
- `tls.connect({ rejectUnauthorized: false })`, `mongoose.connect(uri, { sslValidate: false })`

Python:
- `requests.get(url, verify=False)`, `httpx.Client(verify=False)`
- `ssl._create_unverified_context()`, `ssl.SSLContext(ssl.PROTOCOL_TLS); ctx.verify_mode = ssl.CERT_NONE`
- `urllib.request.urlopen(url, context=ssl._create_unverified_context())`
- `aiohttp.TCPConnector(ssl=False)`, `pymongo.MongoClient(uri, tlsAllowInvalidCertificates=True)`
- Monkey-patching: `ssl._create_default_https_context = ssl._create_unverified_context`

Java:
- A custom `X509TrustManager` whose `checkServerTrusted` body is empty or only logs
- `TrustManager[]` built with `new X509TrustManager() { ... all methods no-op ... }`
- `HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())` with a trust-all `SSLContext`
- `Apache HttpClient` with `setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)`

Go:
- `&tls.Config{ InsecureSkipVerify: true }` in `http.Transport`, `grpc.Dial` `grpc.WithInsecure()`/`WithTransportCredentials(insecure.NewCredentials())`
- `crypto/tls.Dial(network, addr, &tls.Config{ InsecureSkipVerify: true })`

.NET:
- `ServicePointManager.ServerCertificateValidationCallback = (s, c, h, e) => true`
- `HttpClientHandler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errs) => true`
- `HttpClientHandler.ServerCertificateValidationCallback = ...`

PHP / Ruby / others:
- PHP cURL: `CURLOPT_SSL_VERIFYPEER` set to `false` (and `CURLOPT_SSL_VERIFYHOST` to `0`)
- Ruby: `OpenSSL::SSL::VERIFY_PEER` overridden, `Net::HTTP` with `verify_mode: OpenSSL::SSL::VERIFY_NONE`, `Faraday`/`HTTParty` with `verify: false`

## False positives
- Verification is enabled and a custom CA bundle is supplied for a legitimately private CA (corporate proxy, internal mTLS): `ca: fs.readFileSync('corp-ca.pem')` with `rejectUnauthorized` left at its default `true`. This is correct, not a bypass — confirm the default is unchanged.
- Verification is disabled inside a unit/integration test that points at `localhost` / a test container with a throwaway self-signed cert, and the code path is gated by a test-only entrypoint or `if (process.env.NODE_ENV === 'test')`.
- mTLS client-cert configuration is sometimes confused with server validation: presenting a client cert does not by itself disable server verification — check both flags independently.
- A proxying component (envoy, nginx) terminates TLS upstream and re-establishes it with mTLS on a trusted internal network — verify the trust boundary, but the application-level flag may be intentional there.

## Attack scenario
1. The application connects to a payment gateway with `rejectUnauthorized: false` because the original integration threw an expired-cert error and an engineer "fixed" it by disabling verification.
2. The attacker positions themselves on the network path: compromised Wi-Fi, ARP spoofing on a cloud VPC, a malicious corporate proxy, or a BGP hijack of the gateway's IP.
3. The attacker presents any certificate (self-signed is enough) and completes the TLS handshake — the client accepts it without question.
4. The attacker now sits bidirectionally in the middle: they read payment/PII data in cleartext (post-TLS-decrypt) and can tamper with requests and responses — redirect payouts, swap account numbers, inject fraudulent amounts.
5. Because the connection "works," no error is logged; the compromise persists undetected until discovered by an unrelated audit.

## Impact
- **Confidentiality**: full disclosure of all data on the channel — credentials, tokens, PII, payment data, internal API payloads. The attacker sees plaintext that TLS was supposed to protect.
- **Integrity**: the attacker can modify requests and responses in both directions — forge API calls, alter transaction details, inject malicious responses that exploit client-side deserialization or parsing.
- **Availability**: less directly affected, but a MITM can drop or corrupt traffic; with mTLS, stolen credentials can be replayed to impersonate the client.
- Severity scales with what the channel carries: a verification bypass on a telemetry endpoint is Medium; on a payments, identity-provider, database, or admin-API channel it is **Critical** (often CVSS 8–9+). A process-global disable (`NODE_TLS_REJECT_UNAUTHORIZED=0`) makes every outbound connection in the process vulnerable at once.

## Remediation
Never disable verification to "fix" a handshake error — diagnose the chain:
```ts
// VULNERABLE — masks the real problem (expired/missing cert) and disables all auth
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
https.get('https://api.partner.example.com/charge', { rejectUnauthorized: false }, cb);

// SAFE — fix the trust chain; keep verification on, supply the partner's CA if private
const CA = fs.readFileSync(path.join(__dirname, 'partner-ca.pem')); // only if a private CA
https.get('https://api.partner.example.com/charge', { ca: CA /* rejectUnauthorized defaults to true */ }, cb);
```
For Python use `verify=True` (the default) and add a private CA via `verify='/path/to/ca-bundle.pem'`; for Go leave `InsecureSkipVerify` unset and use `RootCAs`; for Java use the default `TrustManager` and load the partner cert into a `TrustStore`. For high-value integrations, layer **certificate pinning** (pin the SPKI/hash of the leaf or intermediate) on top of standard validation so that even a compromised publicly trusted CA cannot impersonate the partner. Treat any `rejectUnauthorized:false`/`verify=False`/`InsecureSkipVerify:true` outside test code as a release-blocking defect and add a CI grep guard.

## References
- OWASP ASVS V9.2.x — Communications security, server TLS verification and certificate pinning
- OWASP WSTG-CRYP-03 — Testing for weak SSL/TLS ciphers, weak configuration, and certificate validation
- OWASP Cheat Sheets: TLS Pinning, Transport Layer Protection
