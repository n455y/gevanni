---
id: P101
name: gRPCWebSocketAuth
area: V4 API and Web Service
refs: ASVS V3.4.x, V13.x / WSTG-ATHN-01, WSTG-ATHZ-01 / CS: REST Security, GraphQL Cheat Sheet
---

# P101 — gRPC / WebSocket Authentication & Authorization

## Overview
gRPC and WebSocket (WS) connections are **long-lived and stateful** at the transport layer, which inverts the per-request authentication model that ordinary HTTP APIs rely on. The recurring flaw is authenticating the *connection* once (the gRPC handshake, the WS `Upgrade` request) and then trusting every subsequent stream message or frame for the connection's lifetime. A token that expires, a role that is revoked, or a resource that the caller should no longer reach all remain accessible until the socket closes. The root cause is twofold: (1) auth logic is wired into the connect/intercept path only, and (2) authorization is never re-evaluated per message, per stream call, or after token expiry — so a single successful handshake grants a standing privilege window.

## What to check
- On **gRPC**: is authentication enforced by a **server-side interceptor** that runs for *every* unary/streaming call, or only at channel/connection setup?
- On **WebSocket**: is the `Upgrade`/handshake the *only* place credentials are checked, with no per-message authorization in the `on('message')` handler?
- Are **token expiry** and **revocation** honored mid-session? Does the server close the stream/socket when the access token TTL elapses, or does the connection stay alive on a stale credential?
- Is the **origin** validated against an allow-list on the WS handshake (`Origin` header)? Is the binding `wss://` (TLS) enforced, or are plain `ws://` connections accepted?
- Are **per-method / per-message authorization** checks present (does the caller's role/claims permit *this* RPC or message type)? gRPC method name (`/pkg.Svc/Method`) and WS message `type` are the resources to gate.
- Are auth tokens passed through **metadata** (gRPC) / **query string or subprotocol header** (WS) — and if query string, are they leaked into server/proxy access logs?
- Does the WS path rely on a **cookie** inherited from the browser origin? If so, is CSRF protection (Origin check, per-message token) present, since a cross-site page can open an authenticated WS just like a form POST?
- For **streaming** RPCs, is authorization checked once at stream *open* but never re-checked if the caller's permissions change mid-stream?
- Is a **reconnection/refresh** flow re-validated, or can a replayed handshake `Sec-WebSocket-Protocol` / token reuse a session indefinitely?

## Static signals
gRPC — interceptor missing or auth only at connect:
- `interceptors:` block absent on the server builder, or `ServerInterceptor` that does **not** read/verify `Authorization` from `Metadata`
- Go: `grpc.NewServer()` with **no** `grpc.UnaryInterceptor` / `grpc.StreamInterceptor`; or interceptor that only logs
- Java gRPC: `serverBuilder.addService(...)` with **no** `ServerInterceptor`; `@GrpcService` without an auth interceptor in the chain
- Python grpc: `grpc.server(executor)` with **no** `interceptors=[AuthInterceptor()]`
- Node `@grpc/grpc-js`: `new grpc.Server()` handlers that call `call.metadata.get('authorization')` inconsistently across methods (per-method, not centralized)

WebSocket — handshake-only auth:
- `wss.on('connection', (ws, req) => { ... })` with **no** `ws.on('message', ...)` authorization
- `WebSocketServer({ ... })` / `ws` (Node) with **no** `verifyClient` / `handleUpgrade` override performing Origin + token checks
- `accept()` / `handleUpgrade` returns the socket without capturing the authenticated principal for per-message checks
- `socket.onmessage`, `session.Subscribe`, `OnMessage` (C#), `onmessage` that dispatches by `type` **without** a `can(user, type)` guard

Origin / transport gaps:
- `new WebSocketServer({ ... })` with **no** `verifyClient` (Node `ws`)
- Gorilla `websocket.Upgrader{ CheckOrigin: func(r *http.Request) bool { return true } }` — wildcard origin
- `ws://` URLs accepted in production config / hardcoded (no TLS)
- Tokens in `new WebSocket('ws://host?token=' + jwt)` — query-string credential leak

Expired-token persistence:
- Auth state captured once: `const user = verify(req.headers); wss.on('connection', ws => { ws.user = user })` with **no** refresh / re-verify timer
- Python: `await websocket.accept(); user = decode(token)` then `async for msg in websocket.iter_text()` with no re-check
- gRPC streaming server handler runs an open `while True: yield` loop with no periodic re-auth

## False positives
- A **server-side gRPC interceptor chain** verifies the token on every unary *and* streaming call, extracts the principal, and a per-method authorization check (e.g., `/pkg.Svc/Delete` requires `admin`) runs inside each handler — protected.
- The WS `verifyClient`/`handleUpgrade` enforces a strict **Origin allow-list** AND the `on('message')` handler calls `authorize(user, msg.type)` per message AND the server closes the socket on token expiry — protected.
- The transport is purely internal (mTLS between two trusted services in a sealed network) with no end-user identity crossing it — auth may legitimately live at the edge gateway. Confirm the gateway *does* enforce it.
- The token passed in the WS handshake is a **short-lived one-time ticket** exchanged immediately for a session bound to per-message authorization — not a long-lived bearer reused as-is.

## Attack scenario
1. Attacker obtains (or phishes) a valid JWT for a low-privilege user, or steals a session token via XSS (P38/P40).
2. Attacker opens a WebSocket: `new WebSocket('wss://app.example.com/ws?token=' + stolenJwt)`. The server authenticates the `Upgrade` request and accepts the connection.
3. Over the next hours, the legitimate user's session is revoked and the JWT expires — but the server never re-checks; the WS stays open.
4. Attacker sends message frames for privileged operations (`{type: "admin.purge", ...}`) the caller's role should never allow. With no per-message authorization, the server executes them.
5. On gRPC, the attacker opens a long-lived stream to `/pkg.Audit/Stream` once authorized, then keeps reading after their role is downgraded — the stream never re-authorizes.

## Impact
- **Confidentiality**: stale/revoked sessions keep reading sensitive stream data; cross-origin CSWSH can read authenticated state.
- **Integrity**: per-message authorization gaps let a low-privilege socket invoke privileged RPCs/message types — full account or tenant takeover.
- **Availability**: an open, unauthenticated or stale-credential socket can be abused for resource exhaustion (unbounded subscriptions, broadcast flooding).
- Severity scales with the privilege lifetime the socket grants: a once-privileged user whose session should have ended but the connection persists is effectively a **standing privilege escalation**.

## Remediation
Enforce auth in the connection path *and* re-evaluate per message; never trust the handshake alone:
```ts
// VULNERABLE — auth only at connection time
wss.on('connection', (ws, req) => {
  ws.user = verifyToken(getToken(req)); // checked ONCE, never again
  ws.on('message', (m) => handle(ws.user, JSON.parse(m))); // no per-message authz
});

// SAFE — Origin allow-list + per-message authorization + expiry enforcement
const wss = new WebSocketServer({
  verifyClient: ({ origin, req }, cb) => {
    if (!ALLOWED_ORIGINS.has(origin)) return cb(false, 403, 'bad origin');
    const user = verifyToken(getToken(req));
    if (!user) return cb(false, 401, 'bad token');
    req.user = user; req.tokenExp = user.exp;
    cb(true);
  }),
});
wss.on('connection', (ws, req) => {
  const reauth = setInterval(() => { if (Date.now()/1000 > req.tokenExp) ws.close(4401, 'expired'); }, 30_000);
  ws.on('close', () => clearInterval(reauth));
  ws.on('message', (raw) => {
    const m = JSON.parse(raw);
    if (!can(req.user, m.type)) return ws.close(4403, 'forbidden'); // per-message authz
    handle(req.user, m);
  });
});
```
For gRPC, put verification in a server `UnaryInterceptor` + `StreamInterceptor` and do method-level authorization in each handler; for streaming RPCs, re-check claims periodically and cancel the stream on revocation. Defense-in-depth: prefer `wss://` (TLS), short-lived tokens with server-side expiry enforcement, and `verifyClient` Origin allow-lists over CORS-style wildcard reflection.

## References
- OWASP ASVS V3.4.x — Token-based session management (lifetime, revocation, re-authentication)
- OWASP ASVS V13.x — API and web service access control (per-call authorization)
- OWASP WSTG-ATHN-01, WSTG-ATHZ-01 — Testing for authentication / authorization bypass
- OWASP Cheat Sheets: REST Security, GraphQL Cheat Sheet (per-field/per-query authz parallels per-message authz)
