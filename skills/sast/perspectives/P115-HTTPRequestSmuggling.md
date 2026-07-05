---
id: P115
name: HTTPRequestSmuggling
refs: ASVS V14.x / PortSwigger Request Smuggling / CS: Request Validation
requires: [backend]
---

# P115 — HTTPRequestSmuggling

## Overview
HTTP Request Smuggling (HTTP desync) occurs when a front-end component (reverse proxy, load balancer, CDN, WAF) and a back-end server **disagree on where one HTTP request ends and the next begins**, so that bytes an attacker prepends or appends to a request are interpreted by the back-end as the start of the *next* victim request. The root cause is a parsing discrepancy around the `Content-Length` (CL) and `Transfer-Encoding` (TE: `chunked`) headers — the classic CL.TE, TE.CL, and TE.TE variants — plus newer HTTP/2→HTTP/1.1 downgrading desync (H2.CL, H2.TE, CRLF injection via pseudo-headers) and header-length ambiguities (`Content-Length` on GET, duplicate headers, obs-fold). Because the smuggling happens *between* trusted tiers, TLS, mutual auth, and WAF rules at the front-end do nothing — the poisoned byte stream is already inside the trusted network.

## What to check
- Does the stack place a reverse proxy, CDN, or load balancer (Nginx, HAProxy, Envoy, Traefik, AWS ALB/CloudFront, Cloudflare, Akamai) in front of an origin that uses a *different* HTTP parser (Tomcat, Jetty, Node `http`, Go `net/http`, Python `gunicorn`/`uWSGI`, PHP-FPM)? Any version skew between the two parsers is the prerequisite.
- Does any tier normalize, rewrite, or strip `Transfer-Encoding` / `Content-Length` instead of **rejecting** ambiguous requests that carry both, or carry malformed values (e.g. `Transfer-Encoding: chunked\x0b`, `Content-Length: 3, 5`, `Transfer-Encoding: xchunked`)?
- Is HTTP/2 (or HTTP/2 over cleartext) terminated at the edge and proxied to an HTTP/1.1 back-end via `Upgrade`/`http2 backend off`? Down-grade conversion is where H2.CL / H2.TE and connection reuse desync live.
- Does the back-end reuse a keep-alive/TCP connection or a pooled connection (gunicorn threaded, Node `keepAlive`, Tomcat `maxKeepAliveRequests`) across multiple front-end requests? Smuggling requires the front-end to keep the connection open and the back-end to read more bytes than the front-end sent.
- Does the front-end forward hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `TE`) instead of stripping them, or does it append `X-Forwarded-For` *after* an attacker-controlled CRLF?
- Are request bodies allowed on methods that should have none (`GET`, `HEAD`, `DELETE` with a `Content-Length`)? Back-ends that ignore CL on GET are prime CL.TE targets.
- Is there any CRLF-injection sink — header reflection, redirect `Location: <user>`, `Set-Cookie` from query, log writer — that lets an attacker inject `\r\n` and synthesize headers or a second request?
- Does the application rely on the front-end's authority for authentication/authorization (e.g. "X-Internal-User" header set by proxy, IP allow-list of the proxy), turning a smuggled request into a request that bypasses auth entirely?

## Static signals
Reverse-proxy / gateway config that forwards instead of rejecting ambiguity:
- Nginx: `proxy_http_version 1.1;` with no `proxy_set_header Connection "";`, missing `proxy_pass_request_headers` hygiene; `underscores_in_headers on`.
- HAProxy: `option http-use-htx` skew vs backend; `http-reuse` (`safe`/`aggressive`/`always`) raising connection reuse.
- Envoy: `h2_upgrade_headers`, `http2` backend without `HTTP/2` end-to-end; `strip_matching_host_header` oddities.
- Cloudflare/AWS ALB in front of Nginx+Tomcat — note version skew; check for documented "request smuggling" CVEs per component version.

Back-end body parsing lenient about CL/TE conflicts:
- Node `http`: manual `req.on('data')` accumulators that ignore `transfer-encoding`; express `req.body` parsers that read CL even when TE is present.
- Python: `gunicorn` sync worker vs `uWSGI --http-socket` vs `BaseHTTPRequestHandler`; custom WSGI servers calling `environ['CONTENT_LENGTH']` without honoring chunked.
- Java: Tomcat `maxHttpHeaderSize`, Jetty `requestBufferSize`; Servlet reading `Content-Length` body while container also parsed chunked.
- Go: `net/http` older versions handling `Transfer-Encoding: chunked, chunked`; hand-written `bufio` readers splitting on `\n` instead of `\r\n`.

CRLF-injection sinks that bootstrap smuggling:
- `res.redirect(req.query.next)` / `response.sendRedirect(userUrl)` (header injection → second request).
- `Set-Cookie` / `Location` built by concatenating user input without `\r\n` rejection.
- Log lines (`logger.info(req.headers['x-...'])`) that go through a streaming proxy.

Cloud / IaC:
- Terraform `aws_cloudfront_distribution` with `viewer_protocol_policy`/origin HTTP/2 mismatch; `aws_lb` HTTP/2 enabled but target group HTTP/1.
- Kubernetes `ingress-nginx` annotations `nginx.ingress.kubernetes.io/backend-protocol: HTTP` with `use-http2: "true"` at edge.

## False positives
- End-to-end HTTP/2 (client→edge→origin) with no HTTP/1.1 hop and no `Upgrade` — H2 framing is length-prefixed, classical CL/TE smuggling does not apply (though H2.H2 request-splitting on buggy intermediaries still can).
- The front-end and back-end are the *same* binary/library version (e.g. Nginx proxying to Nginx with identical config) and both reject ambiguous requests per RFC 7230 §3.3.3.
- Confirmed deployment hardening: front-end rejects (400) any request with both CL and TE, with duplicate/conflicting CL, or with TE values it does not understand — then there is no observable discrepancy to exploit.
- A scan "finding" that only shows a timing differential but cannot be turned into a captured/redirected request — many automated tools false-positive on the differential alone.

## Attack scenario
1. Attacker sends a single request to the front-end crafted so the front-end uses `Content-Length` (forwards N bytes) but the back-end honors `Transfer-Encoding: chunked` (treats the request as ending at `0\r\n\r\n`). Classic CL.TE payload:
   ```
   POST / HTTP/1.1
   Host: vulnerable.example
   Content-Length: 4
   Transfer-Encoding: chunked

   0

   GPOST / HTTP/1.1 ...   <- smuggled prefix, left in the back-end's read buffer
   ```
2. The front-end thinks the request is `4` bytes and closes its view of it; the back-end reads until `0\r\n\r\n` and the remaining `GPOST...` stays buffered on the keep-alive connection.
3. The next victim request arrives on that same reused back-end connection; the back-end prepends the buffered bytes, so the victim's bytes become the *body* of the smuggled `GPOST` (request capture) — or the smuggled bytes redirect/walk the victim's session (request poisoning, web-cache poisoning, credential theft via a captured `POST /login`).
4. HTTP/2 variant: the attacker abuses H2→H/1.1 downgrade, sending a `content-length` pseudo-header that disagrees with the DATA frame lengths, or injects `\r\n` via a header name/value — the down-grade translator emits a malformed H/1.1 request that desyncs the origin.

## Impact
- **Confidentiality**: capture of other users' requests and bodies (login credentials, session cookies, PII) stored or logged by the smuggled request; bypass of front-end TLS/auth.
- **Integrity**: execute actions as other users (request poisoning), poison shared caches so all users receive attacker-controlled responses, bypass front-end security controls/WAF/rate limits.
- **Availability**: drain back-end connection pools, tie up workers, cause cascading 5xx.
- Severity is typically **Critical**: a single desync often yields full account takeover and credential capture across the victim population behind the shared back-end connection.

## Remediation
Reject ambiguous requests at every tier; never let two parsers disagree — favor a single RFC-7230 §3.3.3-compliant decision:
```nginx
# VULNERABLE — front-end forwards whatever the client sent, lets backend parse
location / {
    proxy_http_version 1.1;
    proxy_pass http://backend;
}

# HARDENED — front-end rejects CL+TE, strips hop-by-hop, disables HTTP/2 downgrade where backends are H/1.1
location / {
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header TE "";
    # reject clients sending both Content-Length and Transfer-Encoding
    if ($http_transfer_encoding) { return 400; }
    proxy_pass http://backend;
}
```
On the back-end, disable request body on state-changing-safe methods, reject `Content-Length` on `GET`/`HEAD`, and ensure the container rejects (not normalizes) conflicting CL/TE. Defense-in-depth: run end-to-end HTTP/2 where possible, keep the front-end and back-end parser versions aligned and patched, and avoid relying solely on the front-end for auth on the internal hop — assume an attacker can reach the back-end with smuggled bytes.

## References
- ASVS V14.x
- PortSwigger Request Smuggling
- CS: Request Validation
