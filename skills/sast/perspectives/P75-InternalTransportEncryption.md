---
id: P75
name: InternalTransportEncryption
refs: ASVS V9.1.x / WSTG-CRYP-03 / CS: Transport Layer Protection
requires: []
---

# P75 — InternalTransportEncryption

## Overview
East-west traffic — between the application and its database, cache, message broker, object store, or peer microservices — is frequently left in plaintext under the assumption that "the internal network is trusted." This assumption breaks down the moment an attacker reaches the VPC (compromised pod, SSRF, misconfigured security group, malicious insider, or a co-tenant in a shared subnet) and can sniff or tamper with credentials, PII, and tokens flowing over the wire. The root cause is almost always a connection string or client configuration that omits TLS/mTLS, or an HTTP-based internal API with no service mesh sidecar enforcing encryption. Even ASVS V9 treats internal links as in scope: all hops carrying sensitive data must be encrypted regardless of network topology.

## What to check
- Does every datastore connection (Postgres, MySQL, MongoDB, Redis, Elasticsearch, Memcached, Cassandra) use TLS? Look for `sslmode=require/verify-full`, `tls=true`, `rediss://`, `amqps://`, `ldaps://`.
- Are certificates actually **verified** (`verify-full`, `tlsInsecure=false`, `checkServerIdentity`) rather than bypassed (`sslmode=disable`, `rejectUnauthorized=false`, `InsecureSkipVerify`)?
- Is mutual TLS (client certificates) used for service-to-service auth, or only server auth?
- Are internal HTTP/gRPC APIs called over `https://` / TLS, or plain `http://`?
- Is a service mesh (Istio/Linkerd/Consul Connect) enforcing mTLS mesh-wide, and is anything communicating **outside** the mesh (an external partner, a legacy service, a cloud-managed DB)?
- Are message-broker connections (Kafka, RabbitMQ, SQS-over-VPC-endpoint, NATS) encrypted? Kafka needs `security.protocol=SASL_SSL`/`SSL`, not the plaintext default.
- Are connection strings sourced from config/secrets, and do any hard-coded values use the plaintext scheme (`postgres://`, `mongodb://`, `redis://`, `amqp://`)?
- For cloud-native services: are VPC endpoints / PrivateLink configured to deny plaintext, and is `force_tls` / minimal TLS version (1.2+) enforced?

## Static signals
Plaintext connection schemes and disabled verification:
- Node: `mongoose.connect('mongodb://db:27017/app')`, `redis.createClient({url:'redis://cache:6379'})`, `amqp.connect('amqp://broker')`
- Python: `psycopg2.connect('postgres://...')` without `sslmode`, `redis.Redis(host=...)` (no `ssl=True`), `pika.BlockingConnection(pika.URLParameters('amqp://'))`
- Java: JDBC `jdbc:postgresql://db:5432/app` (no `?sslmode=`), `spring.redis.ssl=false`
- Go: `sql.Open("postgres", "host=db ... sslmode=disable")`, `redis.NewClient(&redis.Options{Addr:"cache:6379"})` (no `TLSConfig`)
- PHP: `new PDO('mysql:host=db', ...)` (no `PDO::MYSQL_ATTR_SSL_*`), `new Redis()` to `tcp://`
- Ruby: `Redis.new(url: 'redis://cache:6379')` (no `rediss://` / `ssl: true`), `PG.connect(host:'db')` without `sslmode`
- `.NET`: `Host=db;` connection string with no `Encrypt=True;TrustServerCertificate=False`

Certificate verification bypassed (TLS present but hollow):
- Node: `rejectUnauthorized: false`, `agent: new https.Agent({rejectUnauthorized:false})`, `NODE_TLS_REJECT_UNAUTHORIZED=0`
- Python: `verify=False` in `requests`, `ssl._create_unverified_context()`, `InsecureRequestWarning`
- Go: `InsecureSkipVerify: true` in `tls.Config`
- Java: `-DtrustProxy`, custom empty `TrustManager`, `setHostnameVerifier(NO_VERIFIER)`
- PHP: `MYSQL_ATTR_SSL_VERIFY_SERVER_CERT=false` with no CA pin
- `.NET`: `TrustServerCertificate=True`

Internal services over plain HTTP:
- `axios.get('http://internal-api/users')`, `requests.get('http://billing-svc')`, `resty.R().get("http://partner-internal")`
- gRPC `grpc.Dial("svc:50051", grpc.WithInsecure())` / `grpc.WithTransportCredentials(insecure.NewCredentials())`

## False positives
- All internal links genuinely carry TLS/mTLS or are inside a mesh that enforces mTLS for every hop, including egress to managed services.
- The link carries no sensitive data AND the threat model explicitly accepts plaintext (rare — note as informational, not secure).
- `localhost` / loopback connections (app to a sidecar on the same pod) where the kernel guarantees locality — still flag if data crosses a container boundary with shared network.
- The DB is reached over a VPC endpoint with enforced TLS but the scheme looks plaintext because a proxy terminates TLS — verify the proxy-to-DB leg is also encrypted.
- A plaintext-looking scheme is actually TLS due to library defaults (e.g. some drivers enable TLS by default) — confirm against the driver docs, don't assume.

## Attack scenario
1. Attacker gains a foothold in the VPC: a compromised pod via an RCE in another service, an SSRF that reaches internal addresses, or a misconfigured security group exposing the DB port.
2. They sniff east-west traffic on the internal subnet (`tcpdump`, ARP spoofing, or a malicious sidecar) and capture plaintext Postgres/Redis credentials and PII queries.
3. With captured DB credentials they connect directly to the datastore, bypassing the application's authZ layer entirely.
4. They exfiltrate or alter records, pivot to an internal HTTP API over plain `http://` to forge calls (e.g. trigger a refund endpoint with no transport-level identity check), and move laterally — all because no hop required TLS or a client certificate.

## Impact
- **Confidentiality**: credential, token, and PII disclosure in transit.
- **Integrity**: interception and tampering of queries/responses, forged internal API calls.
- **Availability**: limited directly, but tampering can corrupt data or trigger destructive actions.
- Severity scales with what traverses the link: a plaintext session-store Redis or credentials-bearing DB connection is High even inside a VPC; a plaintext telemetry endpoint may be Low. Zero-trust non-conformance is at minimum Medium.

## Remediation
Encrypt every internal hop and verify certificates; prefer mTLS for service identity:
```ts
// VULNERABLE — plaintext DB and cache, no TLS
mongoose.connect('mongodb://db:27017/app');
redis.createClient({ url: 'redis://cache:6379' });

// SAFE — TLS with cert verification
mongoose.connect('mongodb+srv://db/app?tls=true&ssl=true');
redis.createClient({ url: 'rediss://cache:6379', socket: { tls: true, rejectUnauthorized: true } });
```
For Postgres prefer `sslmode=verify-full` with a pinned CA over `require` (which encrypts but does not authenticate the server). Enforce a service mesh with mesh-wide STRICT mTLS (Istio `PeerAuthentication`) so plaintext is rejected at the sidecar — defense-in-depth that catches a single misconfigured client.

## References
- ASVS V9.1.x
- WSTG-CRYP-03
- CS: Transport Layer Protection
