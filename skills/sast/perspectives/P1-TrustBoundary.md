---
id: P1
name: TrustBoundary
refs: ASVS V1.x / WSTG-INFO-02, WSTG-ATHZ-01 / CS: Architecture Cheat Sheet, Authorization Cheat Sheet
---

# P1 — TrustBoundary

## Preconditions

The code makes security decisions.


## Overview
A trust boundary is any place where data or control flow crosses from a less-trusted domain (browser, mobile app, third-party API, public network, unauthenticated request) into a more-trusted one (server, internal service, privileged execution context). The defining mistake in this class of flaw is treating data from the untrusted side as if it had already been validated, authenticated, or authorized — e.g. trusting a `role` field posted by the client, treating a JWT payload as authoritative without signature/issuer checks, or inferring identity from spoofable request metadata (IP, User-Agent, `X-Forwarded-For`). Every crossing must re-establish identity and re-authorize on the trusted side; once a value is inside the boundary it is treated as trusted only if the boundary itself enforced the guarantee. When boundaries are missing or leaky, authorization bypass, privilege escalation, and injection all become possible regardless of other defenses.

## What to check
- Are authentication and authorization decisions enforced **server-side**, on every privileged request — never delegated to client-side UI gating, hidden form fields, or route guards that run only in the browser?
- Are privilege-carrying values (`role`, `isAdmin`, `tenantId`, `userId`, `account`) sourced from the **server-established session** (DB row bound to the authenticated principal), not from `req.body` / `req.query` / JWT claims presented by the client?
- If JWTs are used, are `alg`, signature, `iss`, `aud`, `exp`, and `nbf` verified with the correct key and library before any claim is read? (See P5.)
- Does the app authenticate by validating a credential (session cookie / token), or does it guess identity from spoofable metadata (`req.ip`, `X-Forwarded-For`, `User-Agent`, a "magic" header)?
- For multi-tenant or object-scoped resources, is authorization checked against the **object owner/tenant** on the server (IDOR), not merely "is the user logged in"?
- Is server-to-server traffic also authenticated (mTLS, signed tokens, network ACLs), or is "it came from inside the VPC" trusted implicitly?
- Are there hidden boundaries the code ignores — e.g. trusting `localhost` callers, treating a service mesh sidecar as the only gate, or assuming a CDN/WAF sanitized input?
- Does deserialization, file upload, or redirect target cross from external to internal context without re-validation?

## Static signals
Client-supplied value used directly as a privilege/identity fact:
- `if (req.body.role === 'admin')`, `req.body.isAdmin`, `req.query.as === 'su'`
- `const uid = req.body.userId || req.query.uid;` (mass-assignment / parameter-tampering surface)
- `switch (req.body.role)` that gates privileged branches

Claims read from a token without verification context:
- `jwt.decode(token)` (no signature check) vs `jwt.verify(token, key, {algorithms, issuer, audience})`
- trusting `req.user` that was populated from an unverified payload or a header the client sets
- Python: `jwt.decode(token, options={'verify_signature': False})`, reading `payload['role']` after `decode` without `verify`

Identity inferred from metadata:
- `const ip = req.headers['x-forwarded-for']; if (ip.startsWith('10.')) grantInternal();`
- `if (req.get('user-agent').includes('Internal'))` or a custom `X-Admin: 1` header used as an auth factor
- Go: `r.Header.Get("X-Real-IP")` used to decide trust; Ruby: `request.remote_ip` trusted for S2S

Mass-assignment that lets the client overwrite protected fields:
- `User.update(req.body)` / `Object.assign(user, req.body)` with no allow-list (role, isAdmin, balance writable)
- Django: `ModelForm` / serializer with `fields = '__all__'`; Rails: `update(params[:user])` without strong params (`permit`)

Hidden-field / route-only enforcement:
- `<input type="hidden" name="role" value="user">` then server trusts it
- frontend-only route guards (`router.beforeEach`, React `<ProtectedRoute>`) with no matching server check

Trusting "internal" callers:
- `if (req.hostname === 'localhost')` / `if (connection.remoteAddress === '127.0.0.1')` treated as authentication
- no auth on `/internal/*` or admin endpoints assumed reachable only from the VPN

## False positives
- Genuinely unauthenticated, public endpoints (public profile GET, marketing pages) where there is no privilege to protect — these sit outside any trust boundary by design.
- Authorization is centralized in framework middleware (Express `passport` + a per-route `requireRole`, Spring Security `@PreAuthorize`, Django decorator, Rails `before_action`) and the handler relies on it rather than re-checking — confirm the middleware actually runs for the route and that the principal it sets is verified.
- A client-sent value is used only as an **input** that is later validated server-side against an authoritative source (e.g. `tenantId` is cross-checked against the session's allowed tenants), not trusted as a fact.
- `req.body` fields are safe because they map to an explicit allow-list / DTO with validation, and protected fields are never bindable.

## Attack scenario
1. Attacker inspects a normal request and notices the app sends `{"username":"alice","password":"…"}` plus a `role` field echoed back as `"user"`.
2. Attacker replays the login with `{"username":"alice","password":"…","role":"admin"}` (or tampers a profile-update request to set `isAdmin: true`).
3. The handler binds `req.body` straight onto the user record / reads `req.body.role`, so the server now treats Alice as an admin.
4. Alternatively, on an S2S endpoint, the attacker forges `X-Forwarded-For: 10.0.0.5` (or reaches the service through an SSRF) and passes the `ip.startsWith('10.')` internal-only check without any credential.
5. The attacker creates accounts, exfiltrates other tenants' data, or pivots to internal services — full authorization bypass.

## Impact
- **Confidentiality**: cross-tenant data exposure, access to other users' records, internal service data leakage.
- **Integrity**: privilege escalation to admin, fraudulent state changes, account takeover, poisoning of internal pipelines.
- **Availability**: an attacker granted admin/internal trust can delete or lock out resources, trigger destructive internal jobs.
- Severity scales with what the breached boundary protects: a missing boundary in front of a payment/admin surface is Critical; in front of a low-value public action it may be Informational.

## Remediation
Source every privilege-carrying fact from the server-established principal; never bind untrusted input onto sensitive fields.
```ts
// VULNERABLE — client controls the privilege
const role = req.body.role;
if (role === 'admin') grantAdmin();

// SAFE — role comes from the verified session record, not the request body
const role = session.user.role;            // resolved at login from the DB
const allowed = req.body.tenantId;          // cross-checked, not trusted
if (!session.user.tenants.includes(allowed)) return 403;
```
For object/tenant-scoped access, always load the resource and verify `resource.ownerId === principal.id` server-side. Deny-by-default at every boundary, and treat all network input — including from "internal" callers — as untrusted unless an authenticated channel (mTLS, verified token) proves otherwise. Defense-in-depth: combine centralized authorization middleware with explicit per-handler ownership checks so a single missed route does not collapse the boundary.

## References
- OWASP ASVS V1.x — Architecture, threat modeling, and trust boundary requirements
- OWASP WSTG-INFO-02, WSTG-ATHZ-01 — Fingerprinting / Testing for bypass authorization scheme
- OWASP Cheat Sheets: Architecture, Authorization, Injection Prevention (mass-assignment)
