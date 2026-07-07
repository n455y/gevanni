---
id: P44
name: SSRF
refs: ASVS V5.3.x / WSTG-INPV-13 / CS: Server Side Request Forgery Prevention
---

# P44 — SSRF

## Preconditions

The code makes outbound network requests.


## Overview
Server-Side Request Forgery (SSRF) occurs when an application takes user-controlled input — a URL, hostname, IP, or redirect target — and the **server itself** issues an outbound request to it (webhook delivery, image/preview fetching, URL import, S3 presigning, PDF rendering, OAuth callback discovery). The root cause is the absence of a hardened boundary between attacker-influenced addresses and internal/infrastructure network space. A vulnerable server becomes a confused deputy: the attacker uses the server's trusted network position to reach resources that should be unreachable from the outside — the cloud metadata endpoint (`169.254.169.254`), loopback services (`127.0.0.1`, `[::1]`), private RFC1918 ranges, internal admin panels, or local files via `file://`. Modern SSRF is frequently severe: hitting the AWS/GCP/Azure IMDS yields credentials, hitting loopback admin ports yields RCE-style pivots, and SSRF is the most common entry to internal-only APIs and broker/queue systems.

## What to check
- Does any handler accept a URL/host/IP from the request (`req.body.url`, `req.query.callback`, webhook target, "import from URL", image proxy, OAuth `discover`/`.well-known`, sitemap/preview fetcher) and have the server open a connection to it?
- Is the **scheme** restricted to an allow-list (`http`/`https`) before resolution? `file://`, `gopher://`, `dict://`, `ftp://`, `ldap://`, `jar://`, `netdoc://` must be rejected — `gopher://`/`dict://` can craft arbitrary TCP/UDP.
- Is validation done on a **resolved IP address**, not just the hostname string? DNS rebinding and CNAME tricks defeat hostname-only checks; resolve once and connect to that exact IP.
- Are link-local (`169.254.0.0/16`), loopback (`127.0.0.0/8`, `::1`), RFC1918 (`10/8`, `172.16/12`, `192.168/16`), and other reserved ranges (`0.0.0.0/8`, `100.64/10`, `fc00::/7`, multicast) blocked *after* DNS resolution?
- Does the HTTP client **follow redirects** (`follow: true`, `maxRedirects`, `redirect: 'follow'`)? Redirects are the classic SSRF-bypass vehicle: an `https://attacker.com` 302 → `http://169.254.169.254/latest/meta-data/` defeats scheme + host checks done on the *original* URL.
- Is a custom `Host` header or `Authorization` header forwarded, allowing the attacker to hit authenticated internal services?
- Does the response body leak back to the attacker (full SSRF) — or only status/timing (blind SSRF, still exploitable against cloud metadata)?
- Are sockets opened by raw address (`net.connect`, `Socket`) from parsed user input, bypassing HTTP-layer controls?

## Static signals
Unvalidated outbound request from request data:
- Node: `fetch(req.body.url)`, `axios.get(req.body.url)`, `request(req.query.target)`, `got(url)`, `node-fetch`, `http.get(url)`
- Python: `requests.get(url)`, `urllib.request.urlopen(url)`, `httpx.get(url)`, `urlopen` from `req.json['url']`
- Java: `new URL(url).openConnection()`, `HttpClient.send(...)`, `RestTemplate.getForObject(url, ...)`, `OkHttpClient.newCall(Request).execute()`
- Go: `http.Get(url)`, `http.NewRequest("GET", url, nil)`, `client.Do(req)`
- PHP: `file_get_contents($url)`, `curl_exec($ch)` with `CURLOPT_URL` from input, `Guzzle::get($url)`
- Ruby: `Net::HTTP.get(URI(url))`, `open(url)`, `HTTParty.get(url)`

No scheme/IP validation around the call:
- absence of `new URL(...)` + `protocol` check before the fetch
- redirect handling left at default (`follow: true`, `allow_redirects=True`, `followAllRedirects`, `followRedirect`)
- raw socket: `net.connect(req.body.host, port)`, `socket.connect((host, port))`

Feature surfaces that frequently hide SSRF:
- webhook registration / "test webhook" buttons
- "import from URL" / RSS / iCal / OPML ingest
- avatar/image proxy, oEmbed/link-unfurl preview, PDF/HTML-to-image rendering
- OAuth/OpenID `issuer`/`discover` from user-supplied config
- cloud function that proxies to "any URL the client sends"

## False positives
- The destination is a **hardcoded** internal host with no request-controlled component (a server always calling its own billing service) — not SSRF.
- A hardened egress proxy is enforced: scheme allow-list + DNS resolution + private-range rejection + redirect re-validation + pinned-IP connection. Confirm *all four* are present; missing any reopens the hole.
- Input is validated against a strict allow-list of domains/URLs (e.g. only `*.example.com`, resolved and pinned) before the request.
- The "internal" address being reached is intentional and authenticated (health-check endpoint with its own auth) — still Medium, since it can be abused for port mapping/timing leaks.
- The fetch result is discarded entirely and timing is normalized — reduces but does not eliminate blind-SSRF metadata risk.

## Attack scenario
1. Attacker registers a webhook (or triggers "preview URL") with target `http://169.254.169.254/latest/meta-data/iam/security-credentials/` on an EC2-hosted app.
2. The server resolves `169.254.169.254` (link-local) — the app's DNS/IP checks, if any, run on a hostname that *is* already an IP, or are skipped.
3. The server fetches the AWS IMDS path and either returns the JSON body to the attacker (full SSRF) or the attacker pivots via the leaked temporary credentials.
4. With stolen `AWS_ACCESS_KEY_ID`/`SECRET_ACCESS_KEY`/`SESSION_TOKEN`, the attacker calls S3, reads other buckets, or escalates IAM — all from outside, using the server's role.
5. Variant: a redirect-bypass — webhook target `https://attacker.com/r` returns `302 Location: http://localhost:6379/` to send Redis `MONITOR`/`CONFIG SET dir` commands to a loopback service (gopher/dict-style SSRF → RCE).

## Impact
- **Confidentiality**: cloud metadata credentials, internal-only API responses, secrets in `file://` reads, internal service enumeration. Often full account/service compromise via IMDS.
- **Integrity**: sending forged requests to internal write endpoints (queue, storage, admin API), Redis/memcached poisoning on loopback.
- **Availability**: abusing internal services, triggering DoS against internal targets, reading unbounded local resources.
- Severity scales with the server's cloud/network trust: a host with an IAM role and IMDSv1 = Critical; loopback-only with no metadata = High; blind, metadata-protected (IMDSv2) = Medium-High.

## Remediation
Resolve once, pin the IP, validate, and re-validate on every redirect:
```ts
// VULNERABLE — fetches whatever the user sends, follows redirects
await fetch(req.body.url, { redirect: 'follow' });

// SAFE — scheme allow-list, resolve+pin IP, reject private ranges, no redirects
const u = new URL(req.body.url);
if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('scheme not allowed');
const ips = await dns.promises.lookup(u.hostname, { all: true });
for (const { address } of ips) {
  if (isPrivate(ipaddr.parse(address))) throw new Error('internal address blocked');
}
// pin to the resolved IP, preserve Host header, disable redirects or re-validate each hop
await fetch(`${u.protocol}//${ips[0].address}${u.pathname}${u.search}`, {
  redirect: 'manual',
  headers: { host: u.hostname },
});
```
Defense-in-depth: deploy an **egress proxy/firewall** that blocks RFC1918 + link-local at the network layer (so a code bug can't reach metadata), enforce **IMDSv2** (token-required) on all cloud instances, and run the URL-fetching worker in a separate network segment with no access to internal services.

## References
- ASVS V5.3.x
- WSTG-INPV-13
- CS: Server Side Request Forgery Prevention
