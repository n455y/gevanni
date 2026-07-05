---
id: P114
name: WebSocketSecurity
area: V4 API and Web Service
refs: ASVS V13.x / WSTG-CLNT / CS: WebSocket Security
requires: [backend, websocket]
---

# P114 — WebSocketSecurity

## Overview
WebSockets upgrade a single HTTP request into a persistent bidirectional TCP channel that bypasses most of the browser's normal request defenses — the Same-Origin Policy does not constrain a WebSocket's *server* endpoint, standard CSRF tokens are absent from frames, and once the handshake succeeds the connection stays open with whatever privileges the upgrade was granted. Two root-cause classes dominate: (1) **cross-site WebSocket hijacking (CSWSH)**, where the server fails to validate the `Origin` header, allowing any malicious page to open an authenticated socket using the victim's implicit credentials (cookies, HTTP auth); and (2) **authorization modeled only at the handshake**, where every subsequent frame is trusted as the authenticated user even though the protocol carries no per-message re-authentication and messages routinely target other users' resources (DMs, rooms, document IDs). Add `ws://` plaintext, missing frame size/rate limits, and secrets shipped over the wire, and the channel becomes a durable backdoor into the application.

## What to check
- Does the server **validate the `Origin`** header on the upgrade request against an allow-list and reject unrecognized origins? An empty or wildcarded Origin check is equivalent to none.
- Is the connection authenticated **only** at handshake time (cookie/JWT on the GET) with no re-verification of authorization on inbound messages? Check whether each `on('message')` / `on_message` re-checks the user's rights over the targeted resource.
- Does any handler act on a resource identifier supplied *in a frame* (room id, user id, document id, account id) without confirming the authenticated socket owns/can-access it? (IDOR over WebSockets.)
- Is the endpoint served over **`wss://`** (TLS) exclusively, with HSTS on the parent origin and any `ws://` endpoint redirecting or refused? Search for `ws://` literals, especially with tokens/secrets in the URL.
- Are **session credentials transmitted in the query string** of the upgrade URL (`new WebSocket('wss://host/socket?token=...')`)? Query strings are logged by proxies/CDNs and leak via `Referer`.
- Are there **message size and rate limits** per socket (`maxPayload`, ping/pong heartbeat, slow-consume backpressure)? Unbounded frames enable memory exhaustion; unframed flooding enables DoS.
- Is there a heartbeat/idle timeout that closes dead sockets, and a cap on concurrent connections per user/IP to prevent resource exhaustion?
- Does the server broadcast sensitive data to all subscribers of a channel without filtering by the recipient's permissions (leaking other users' data)?
- Are deserialization sinks reachable from frame payloads (JSON parsed then passed to `eval`/template/SQL), and is frame content validated against a schema?
- In the browser client, is the WebSocket URL constructed from `location.host` (so it tracks the deployed origin) rather than hardcoded to an IP or `ws://`?

## Static signals
Origin skipped or wildcarded on upgrade:
- `new WebSocketServer({ server })` with no `verifyClient` / `handleUpgrade` Origin check (Node `ws`)
- Socket.IO: `io.use((socket, next) => next())` with no auth/Origin check; `io.origins('*')` or `io.set('origins', '*:*')`
- Python: `websockets.connect(uri)` client over `ws://`; `@app.websocket('/ws')` (Starlette/FastAPI) handler that never reads `websocket.headers['origin']`
- Go (`gorilla/websocket`): `Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}` — the canonical CSWSH smell
- Java (Spring `@ServerEndpoint`, Tyrus): no `Configurator`/`Origin` rule, or `@ServerEndpointConfig.Configurator` returning true for all origins
- PHP (Ratchet): `new App()` without an `Origin` check in `onOpen`; ReactPHP `WebSocketServer` with no middleware
- Ruby (ActionCable): `config.action_cable.disable_request_forgery_protection = true`; `config.action_cable.allowed_request_origins` empty/unset

Secrets in the URL / plaintext transport:
- `new WebSocket('ws://' + host + '/ws?token=' + token)`
- `new WebSocket('ws://10.0.0.5:8080')` (cleartext, internal IP)
- `wss` URL but token passed as `?api_key=` / `?access_token=` query param

Handshake-only auth, no per-message authorization:
- `socket.handshake.auth` / `socket.handshake.headers.cookie` read once; `socket.on('message', msg => { /* acts on msg.toUserId without re-check */ })`
- `rooms[message.roomId].broadcast(message)` with no membership test
- `db.query('UPDATE docs SET ... WHERE id=' + message.id)` inside an `onMessage` — SQLi/IDOR reachable from a frame

Missing limits:
- `new WebSocketServer({ port: 8080 })` with no `maxPayload`, `maxHttpBufferSize`, or `pingInterval`/`pingTimeout`
- No `socket.binaryType` / no length check before processing; JSON.parse on arbitrary-size payloads

## False positives
- The library enforces Origin by default and it was not disabled (ActionCable forgery protection **on** and `allowed_request_origins` set; Django Channels `AllowedHostsOriginValidator` in the ASGI stack; Spring with `setAllowedOrigins` set explicitly and no `*`). Confirm the check is present and not wildcarded.
- The application uses a **per-connection token** that is sent as the first *authenticated frame* (not a cookie) and is required for every privileged action — i.e., not relying on ambient browser credentials, so CSWSH does not apply.
- The socket is purely server-to-client telemetry (broadcast-only, no client-actuated state) and carries no sensitive data, so per-message authz is moot.
- The endpoint is internal/loopback only and never reachable from a browser context.
- `ws://` on `localhost` for local dev tooling (HMR/dev server) — verify it is not shipped to production.

## Attack scenario
1. Victim is logged in to `wss://app.example.com`; the auth session cookie is set for `.example.com`.
2. Attacker lures the victim to `https://evil.example/` which runs `new WebSocket('wss://app.example.com/ws')`. The browser attaches the victim's cookie to the upgrade.
3. The server does not check `Origin: https://evil.example` (or has `CheckOrigin: true`) and upgrades the socket as the victim.
4. Attacker's page drives the socket: sends `{"cmd":"read","room":"admin-notifications"}`. Because authorization was decided once at handshake and the handler trusts the sender, the server streams the victim's private data (or issues actions — transfers, password change, message-as-victim) back over the open channel.
5. Alternatively the attacker points many browsers at the upgrade with no size/rate limit and exhausts server memory (DoS), or reads secrets that were embedded in the `ws://` URL via shared proxy logs.

## Impact
- **Confidentiality**: CSWSH gives the attacker the victim's live data stream and any action the victim can perform over the socket — full account-level read.
- **Integrity**: per-message authorization gaps let a user read/write other users' resources (IDOR), post or transact as them, or poison broadcast channels.
- **Availability**: missing `maxPayload`/rate limits enable memory and connection-exhaustion DoS; hijacked sockets can be weaponized to flood.
- Severity scales with what the socket can do: a read-only notification channel is medium; a socket that can move money, change credentials, or act as an admin terminal is critical. Cleartext `ws://` with a token in the URL raises the floor further (network-level credential capture).

## Remediation
Validate Origin, authenticate with a short-lived token, and authorize every frame:
```js
// VULNERABLE — wildcard origin, cookie-only auth, handshake-trusts-forever
const wss = new WebSocketServer({ port: 8080 });
wss.on('connection', (socket, req) => {
  const user = sessions.get(req.headers.cookie);          // auth once
  socket.on('message', (raw) => {
    const m = JSON.parse(raw);
    rooms[m.roomId].broadcast(m);                         // no membership check
  });
});

// SAFE — strict origin allow-list, bearer token, per-message authorization, limits
const wss = new WebSocketServer({
  server,
  maxPayload: 64 * 1024,                                   // frame size cap
  verifyClient: ({ req }) => {
    const origin = req.headers.origin || '';
    return ALLOWED_ORIGINS.has(origin);                    // explicit allow-list
  },
});
wss.on('connection', async (socket, req) => {
  const user = await verifyTokenFromAuthHeader(req);        // no ambient-cookie reliance
  if (!user) return socket.close(4401, 'unauthorized');
  socket.on('message', (raw) => {
    if (raw.length > MAX) return socket.close(4413, 'too large');
    const m = parseAndValidate(raw);                        // schema-validated
    if (!canAccess(user, m.roomId)) return;                 // per-message authz
    rooms[m.roomId].broadcastFiltered(m, user);             // recipient-scoped
  });
});
```
Serve only `wss://` behind TLS + HSTS, pass tokens via `Sec-WebSocket-Protocol` subprotocol or the first authenticated frame (never the query string), enforce ping/pong heartbeat and idle/concurrency limits, and run the socket endpoint behind the same CSRF-token/anti-replay discipline used elsewhere.

## References
- OWASP ASVS V13.x — API and web service security (transport, authentication, authorization, input validation)
- OWASP WSTG-CLNT — Testing for WebSockets (origin validation, authz, injection over frames)
- OWASP Cheat Sheet: WebSocket Security (CSWSH prevention, token handling, limits)
