---
id: P122
name: WebRTC
refs: ASVS V17.x / WSTG-CLNT / CS: emerging WebRTC
---

# P122 — WebRTC

## Preconditions

The code uses WebRTC.


## Overview
WebRTC lets browsers establish **direct peer-to-peer media and data channels** that bypass the originating web server, using a separate signaling channel to exchange session descriptions (SDP) and Interactive Connectivity Establishment (ICE) candidates. Because the browser itself gathers ICE candidates and exposes local IP addresses, and because DTLS-SRTP keys are negotiated peer-to-peer, misconfigurations leak client network topology, allow unauthenticated or unencrypted streams, and can be abused to turn the victim's browser into a network-probing relay. The root causes are typically: an unauthenticated or spoofable signaling channel (the security of the whole call depends on it yet it is often treated as trusted), TURN credentials issued without scoping or replay protection, ICE candidate handling that exposes private/LAN addresses, and missing enforcement of DTLS-SRTP / SDES fallback.

## What to check
- Is the **signaling channel** (WebSocket / HTTP / Socket.IO / SSE used to exchange SDP and ICE candidates) authenticated and bound to an authenticated user session? Can an attacker inject or modify an SDP offer/answer to MITM or hijack a call?
- Are signaling messages authorized per-peer (does the server verify that user A is actually allowed to call user B, not just that A is logged in)?
- Is peer **identity verified**? Is there an Identity Provider (IdP) integration or out-of-band fingerprint confirmation, or is any peer who completes signaling trusted?
- Are **TURN credentials** time-limited, scoped to a single user / origin, and generated server-side per the TURN REST API (` hmac` over `timestamp:userid`)? Or are static shared TURN `username`/`credential` shipped in client code?
- Are ICE candidates filtered? Does the app expose **host candidates** revealing private/LAN IPs (RFC1918, link-local) and internal network topology, including via mDNS `.local` hostname enumeration?
- Is **DTLS-SRTP enforced** for media (`RTCRtpSender`/`RTCRtpReceiver`) and DTLS for `RTCDataChannel`? Is there any SDES-SRTP or plaintext fallback allowed?
- Are media tracks **authorized** before `addTrack`/`addTransceiver`? Can a caller push a track to a callee who never consented (e.g., autoplay of attacker video/audio, "camfecting")?
- Is `getUserMedia` gated behind an explicit user gesture, and are permissions requested with the minimum necessary (`video`/`audio`/`screen`)?
- Can a malicious page instantiate `RTCPeerConnection` in the background to enumerate local IPs or proxy traffic through the victim's TURN allocation (amplification / relay abuse)?
- Are recorded media / data streams stored server-side with authorization, encryption, and retention controls?
- Does the data channel's application-layer protocol add its own authentication/authorization, or is any connected peer trusted to send commands?

## Static signals
Unauthenticated signaling:
- `io.on('connection', socket => socket.on('offer', o => socket.broadcast.emit('offer', o)))` — no auth, no per-call authorization
- `wss` upgrade with no token check; `socket.handshake.auth` / `socket.handshake.headers.authorization` ignored
- HTTP signaling endpoint `app.post('/signal', (req,res) => relay(req.body))` with no session/user check

Static TURN credentials shipped to client:
- `{ iceServers: [{ urls: 'turn:turn.example.com', username: 'admin', credential: 'P@ssw0rd' }] }`
- Hardcoded TURN secret in front-end: `const turnSecret = 'supersecret'`
- TURN `credential` is a static string rather than a server-generated HMAC + expiry

DTLS / SRTP not enforced:
- `pc.setConfiguration({ iceTransportPolicy: 'relay' })` without verifying DTLS certificate
- Use of legacy SDES / `crypto` lines in SDP; `RTCPeerConnection` with no `certificates` control on older stacks
- Disabling ICE candidate filtering: `RTCPeerConnection({ iceCandidatePoolSize })` plus exposing all candidates; absence of `iceTransportPolicy` / mDNS obfuscation expectations

IP / topology leakage:
- `pc.onicecandidate = e => signaling.send(e.candidate)` — sends host candidates with private IPs to peer/attacker
- Loop iterating `pc.getStats()` / `RTCIceCandidate.address` / `.candidate.candidate` parsed and exfiltrated
- STUN-only (`{ urls: 'stun:...' }`) configuration guaranteeing host candidates reach the remote peer

Unconsented media / camfecting:
- `pc.addTrack(trackFromGetUserMedia)` to a peer who never accepted; `autoplay` on remote `<video>` element
- `getDisplayMedia` / `getUserMedia({ video:true })` requested without a user gesture or with over-broad constraints

## False positives
- The page uses WebRTC purely for STUN-based public-IP lookup in a first-party analytics/anti-fraud context with documented consent — not a vulnerability per se (still review data handling).
- ICE candidate gathering reveals only the **public** IP because `iceTransportPolicy: 'relay'` (TURN-only) or mDNS `.local` obfuscation is in force and host candidates are filtered — confirm before flagging IP leak.
- TURN credentials are short-lived, per-user HMAC tokens generated server-side via the TURN REST API — this is the correct pattern, not a hardcoded secret.
- DTLS-SRTP is the default and there is no SDES/plaintext fallback path; the data channel is ephemeral and carries no sensitive data.
- The signaling channel is a same-origin authenticated WebSocket with per-call ACL checks and IdP-based peer verification — the security model is sound.

## Attack scenario
1. Attacker lures the victim to a malicious page (or compromises the signaling server of a softphone app).
2. The page runs `const pc = new RTCPeerConnection({ iceServers:[{urls:'stun:stun.l.google.com'}] }); pc.createDataChannel('x'); pc.createOffer().then(o=>pc.setLocalDescription(o))`.
3. As ICE gathering runs, the page reads every `onicecandidate` candidate (or `pc.getStats()`) and extracts `RTCIceCandidate.candidate` — surfacing the victim's **private LAN IP**, internal subnet, and any VPN IPv6 address that the NAT would normally hide.
4. The attacker pivots: uses the leaked internal IP to map the corporate network, fingerprint the victim across sessions, or target internal services (SSRF pivot via TURN relay).
5. If TURN credentials were hardcoded in the JS bundle, the attacker reuses them from their own infrastructure to relay arbitrary traffic through the victim organization's TURN server (bandwidth/amplification abuse, masking the attacker's origin).
6. If signaling is unauthenticated, the attacker injects their own SDP answer mid-call, downgrading or MITMing the media stream and impersonating the callee.

## Impact
- **Confidentiality**: leakage of real client IP, internal/LAN topology, VPN presence, and (if media is unencrypted or MITM'd) call audio/video content and data-channel messages.
- **Integrity**: call hijacking, peer impersonation, injection of unconsented media (camfecting) if signaling/identity is not verified.
- **Availability**: abuse of TURN allocations for traffic amplification / relay DoS, resource exhaustion via crafted SDP/ICE floods.
- Severity scales with exposure: a public-facing conferencing or support-call app on a corporate network turns every visitor into a topology probe and potential internal relay.

## Remediation
Authenticate and authorize signaling; scope TURN credentials server-side per call; filter host candidates:
```ts
// VULNERABLE — static TURN creds, unauthenticated signaling relay, all candidates leaked
const pc = new RTCPeerConnection({
  iceServers: [{ urls: 'turn:turn.example.com', username: 'admin', credential: 'hardcoded' }],
});
io.on('connection', s => s.on('offer', o => s.broadcast.emit('offer', o))); // no auth, no ACL
pc.onicecandidate = e => io.emit('candidate', e.candidate.candidate);       // leaks private IPs

// SAFE — server-generated short-lived TURN creds, authenticated per-call signaling, TURN-only relay
const turnCred = await fetch('/api/turn-credential', { credentials: 'include' }).then(r => r.json());
// server returns: { username: `${expiry}:${userId}`, credential: hmac(turnSecret, `${expiry}:${userId}`) }
const pc = new RTCPeerConnection({
  iceServers: [{ urls: 'turn:turn.example.com?transport=tls', username: turnCred.username, credential: turnCred.credential }],
  iceTransportPolicy: 'relay',                 // hides host/LAN candidates behind TURN
  bundlePolicy: 'max-bundle',
  // DTLS-SRTP is mandatory and default for media; data channel uses DTLS — do not allow SDES fallback
});
// signaling server verifies session, checks caller->callee ACL, and (ideally) enforces IdP peer identity
io.use(authMiddleware);                          // reject unauthenticated sockets
io.on('connection', s => s.on('offer', o => authorizeCall(s.userId, o.to).then(ok => ok && io.to(o.to).emit('offer', o))));
```
Defense-in-depth: enforce DTLS-SRTP with no plaintext/SDES fallback, gate `getUserMedia`/`getDisplayMedia` behind explicit user gestures, request minimal track constraints, and consider an out-of-band SAS/fingerprint confirmation for high-assurance calls.

## References
- OWASP ASVS V17.x — WebRTC and real-time communication security
- OWASP WSTG-CLNT — Client-side testing (WebRTC / ICE candidate leakage, TURN credential handling)
- OWASP Cheat Sheet Series: emerging WebRTC security guidance
