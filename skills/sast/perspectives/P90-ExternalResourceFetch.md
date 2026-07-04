---
id: P90
name: ExternalResourceFetch
area: V5 File Handling
refs: ASVS V12.6.x / WSTG-INPV-13 / CS: Server Side Request Forgery, File Upload, OWASP Secure Headers
---

# P90 — ExternalResourceFetch

## Overview
External resource fetch (a.k.a. resource-import SSRF) occurs when a server-side component retrieves a **user-supplied URL** — image import, URL attachment, OpenGraph/OGP preview, link unfurling, webhooks, feed/RSS ingestion, "import from URL" features, PDF/HTML rendering, or web-cache prefetch — without enforcing a strict allow-list of schemes, hosts, and resolved IP addresses. The root cause is treating a URL as opaque input and passing it straight to an HTTP client; the application then makes the outbound request from inside the trust boundary, where it can reach `http://169.254.169.254/` (cloud metadata), `http://127.0.0.1:6379/` (internal Redis/admin), `file:///etc/passwd` (local file read via protocol abuse), or `gopher://`/`dict://` to speak raw bytes to internal services. Redirect-following silently re-targets a "validated" URL to a private address, so validation must run on the **post-resolution, post-redirect** socket, not the input string. This is the resource-manipulation sibling of P44 (SSRF); it concentrates on the *fetch* pathways rather than direct request forwarding.

## What to check
- Does any endpoint accept a URL (`req.body.url`, `imageUrl`, `feedUrl`, `webhook_url`, `avatar`, `og_url`) and issue a server-side request? Map every HTTP-issuing call site (`fetch`, `axios`, `requests`, `HttpClient`, `net/http`).
- Is the **scheme** restricted to an allow-list (`http`/`https` only)? `file://`, `gopher://`, `dict://`, `ftp://`, `ldap://`, `jar://`, `netdoc://` (Java), `ssrf://`, `data:` all bypass naive host checks.
- Is the **host** resolved to an IP and validated against a private-range blocklist (RFC1918 `10/8`, `172.16/12`, `192.168/16`, loopback `127/8`, link-local `169.254/16`, IPv6 `::1`, `fc00::/7`, IPv4-mapped IPv6 `::ffff:127.0.0.1`)?
- Does the client **follow redirects** by default? A 30x from `http://attacker.com/` to `http://169.254.169.254/` defeats pre-flight validation unless the check is re-run after each hop (or redirects are disabled and resolved manually).
- Is DNS rebinding possible? A hostname resolving to a public IP at validation time but a private IP at connect time evades single-lookup checks. Pin the resolved IP into the socket connection.
- Are responses from internal endpoints returned to the attacker (full SSRF read) or used only as a status/size (blind SSRF)?
- For file fetch (P45-FileUpload companion), is the downloaded content re-validated (magic bytes, size, MIME) before storage/processing? A `Content-Type` header is attacker-controlled.
- Does the client reuse server credentials / cloud IAM role / a metadata-capable network position? Internal requests then carry ambient trust.

## Static signals
Unvalidated user URL passed to an HTTP client:
- Node: `fetch(req.body.url)`, `axios.get(req.body.imageUrl)`, `request(req.body.url)`, `got(url)`, `http.get(body.url)`
- Python: `requests.get(request.json['url'])`, `urllib.request.urlopen(url)`, `httpx.get(url)`, `urlopen(...)` in feed/image/scrape code
- Java: `new URL(body.getUrl()).openConnection()`, `HttpClient.send(...)`, `RestTemplate.getForObject(url, ...)`, `Jsoup.connect(url).get()`, `ImageIO.read(new URL(url))`
- Go: `http.Get(r.URL.Query().Get("url"))`, `http.DefaultClient.Get(url)`, `(&http.Client{}).Get(url)`
- Ruby: `URI.parse(params[:url]).read`, `Net::HTTP.get_response(URI(url))`, `open(url)` (Kernel#open — also command-injection capable)
- PHP: `file_get_contents($_GET['url'])`, `curl_exec($ch)` with `CURLOPT_URL` from input, `get_headers($url)`

Scheme-handling sinks that read local/system resources:
- Java `new URL(url)` accepts `file:`, `jar:`, `netdoc:`, `gopher:`; `URLConnection.getInputStream()`
- PHP `file_get_contents('file://...')`, `fopen`, `copy` with stream wrappers (`phar://`, `compress.zlib://`)
- Python `urllib`-family handlers; `Image.open(url)` (Pillow) following `file://`

Redirect-following defaults (validation bypassed on hop):
- `requests.get(url)` — follows redirects by default
- `axios.get(url)` — follows up to `maxRedirects` (5)
- Go `http.Client{}` — follows up to 10 redirects
- Java `HttpURLConnection` — follows redirects by default
- `curl` with `CURLOPT_FOLLOWLOCATION` set

Absence of post-resolution IP checks:
- No `ipaddress.ip_address(...).is_private` / no `ipaddr.Parse(...).IsPrivate()` / no `InetAddress` range test
- Socket dial uses the hostname, not a pinned resolved IP (DNS rebinding window)

## False positives
- The URL is server-generated or selected from a hardcoded allow-list (e.g. webhook target chosen from a configured dropdown), not request-controlled.
- A pinned egress proxy (forward proxy / NAT gateway) with its own SSRF filtering sits in front of the fetcher, and the host allow-list is enforced at the proxy.
- The resolved IP is validated *and* pinned into the connection (custom `DialContext` / `HTTPAdapter` / `SSLSocketFactory`), redirects are disabled or re-validated each hop, and non-`http(s)` schemes are rejected.
- The fetched resource is re-validated by magic bytes / size cap / MIME allow-list, and the result is never executed or served as HTML.
- The fetcher runs in an isolated network namespace / sidecar with no route to the metadata service or internal subnets (network-level defense — confirm it is actually enforced).

## Attack scenario
1. The app exposes "import avatar from URL": `POST /profile/avatar { "url": "..." }` and calls `fetch(url)` server-side.
2. Attacker submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/WebAppRole/` (AWS IMDSv1). The server fetches it from inside the VPC and returns the body or stores the image bytes (whose size/content leak the response).
3. With stolen temporary credentials the attacker enumerates S3, reads secrets, or pivots further.
4. Variant A (redirect bypass): `http://attacker.com/redir` returns `302 → http://169.254.169.254/...` — defeats pre-flight host validation when redirects are followed.
5. Variant B (DNS rebinding): `evil.com` flips its A record between the validation lookup (public IP) and the connect (private IP), landing the request on the internal admin panel.
6. Variant C (scheme abuse): `file:///etc/passwd` or `gopher://127.0.0.1:6379/_SET%20...` reads local files or speaks raw bytes to internal services.

## Impact
- **Confidentiality**: read internal-only endpoints (cloud metadata, `/metrics`, admin consoles, Redis/Espresso/Memcached), exfiltrate secrets, IAM credentials, internal network topology.
- **Integrity**: with `gopher://`/raw-socket schemes, write to internal services (Redis `SET`, Memcached `set`, internal API `POST`) — pivot to RCE.
- **Availability**: abuse as an open proxy/amplifier; hammer internal services; trigger expensive processing on a URL bomb.
- Severity scales with what the fetcher can reach: cloud metadata = critical (credential theft → full account compromise); loopback-only service enumeration = high; blind SSRF without readback = medium-high.

## Remediation
Reject-by-default: allow-list schemes, resolve the host, reject private/loopback/link-local IPs, pin the resolved IP into the socket, and re-validate on every redirect hop.
```ts
// VULNERABLE — fetches whatever the user supplies, follows redirects
const img = await fetch(req.body.imageUrl);

// SAFE — scheme allow-list, post-resolution IP check, pinned connection, no redirects
import { request } from 'undici';
import { lookup } from 'node:dns/promises';
import ipaddr from 'ipaddr.js';

async function safeFetch(rawUrl: string) {
  const u = new URL(rawUrl);
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('bad scheme');

  const { address } = (await lookup(u.hostname))[0];
  const parsed = ipaddr.parse(address);
  const range = parsed.range();                 // 'private' | 'loopback' | 'linkLocal' | 'unicast' ...
  if (range !== 'unicast') throw new Error('blocked range');

  // Pin the validated IP; set Host header so vhosts resolve; disable redirect-following
  return request(`${u.protocol}//${address}${u.pathname}${u.search}`, {
    method: 'GET',
    headers: { host: u.host },
    maxRedirections: 0,
  });
}
```
Defense-in-depth: run the fetcher in a restricted network namespace/egress proxy with no route to the metadata IP (`169.254.169.254`) or RFC1918 ranges, cap response size, and re-validate the fetched bytes (magic bytes, MIME allow-list, max dimensions) before storage or rendering.

## References
- OWASP ASVS V12.6.x — SSRF and outbound request validation (Files & Resources)
- OWASP WSTG-INPV-13 — Testing for Server Side Request Forgery
- OWASP Cheat Sheets: Server Side Request Forgery Prevention, File Upload, Injection Prevention
- Cloud metadata hardening: AWS IMDSv2 / GCP metadata-header / Azure managed-identity requirements
