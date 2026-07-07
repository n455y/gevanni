---
id: P113
name: SAMLSecurity
refs: ASVS V2.x / WSTG-ATHN / CS: SAML Security
---

# P113 — SAMLSecurity

## Preconditions

The code implements SAML.


## Overview
Security Assertion Markup Language (SAML) lets an Identity Provider (IdP) vouch for a user to a Service Provider (SP) via a signed XML assertion passed through the user's browser. Because the assertion is delivered over the untrusted browser channel and is consumed by a generic XML parser, the security of the flow depends on **three independent checks** that are frequently implemented only partially: the signature must cover the *semantically meaningful* element (not merely be present and valid), the assertion's lifecycle constraints (audience, recipient, NotOnOrAfter, InResponseTo) must be enforced, and the XML must be parsed without enabling external entities or accepting wrapped/mutated document shapes. The single most common root cause is verifying a signature that covers one element while the application then trusts a *different* element the signature did not cover — the XML Signature Wrapping (XSW) class of flaws.

## What to check
- Is the **signature verified against the IdP's trusted certificate** (pinned/rotated), and does the signature cover the element the application actually reads claims from? Validating a signature over `<Assertion>` A but consuming `<Assertion>` B (XSW) is the canonical bug.
- Does the SP bind the verified signature to the exact node it consumes, or does it re-query the DOM (e.g. `getElementsByTagName('Assertion')[0]`) after a separate `verify()` call on another node?
- Are **AudienceRestriction** and **Recipient** enforced against the SP's own entityID and ACS URL? A forwarded assertion from another SP must be rejected.
- Is **InResponseTo** validated against an outstanding AuthnRequest id the SP actually issued (replay/request-correlation)? Unauthenticated "IdP-initiated" SSO should be explicitly disabled or tightly bounded.
- Is **NotOnOrAfter / SubjectConfirmationData NotOnOrAfter** and **SessionNotOnOrAfter** checked, and is there a clock-skew tolerance that isn't excessive (minutes, not hours)?
- Is **RelayState** treated as untrusted? It must not be used to carry identity/role data or be reflected unencoded into a redirect (open redirect / CSRF token fixation).
- Is the ACS endpoint stateless-but-replay-safe? Replaying the same assertion twice must be detected (one-time use, nonce/InResponseTo cache with TTL).
- Does the XML parser **disable external entities / DTD** (XXE) and reject comments where they could break signature semantics? SAML comments can alter canonicalization (C14N) and are an XSW vector.
- Is signature **replay across SPs** prevented (assertion scoped via Audience/Recipient), and are signed assertions ever accepted over unsigned, IdP-initiated flows?
- Are errors surfaced without leaking the raw SAML response, certificate, or internal entity IDs?

## Static signals
Signature verified on a different node than consumed (XSW-prone):
- Java (OpenSAML / Spring Security SAML): `SignatureValidator.validate(signature)` followed by `response.getAssertions()` or `getElementsByTagNameNS(...,"Assertion")` without `isSigned()` + node-binding checks.
- `validator.validate(signature)` then iterating `response.getOrderedAssertions()` / trusting the *first* assertion.
- `samlMessageStorage` / replay cache disabled: `SAML2Bootstrap`, `MessageReplayCheckingFactory` removed, `isReplayProtected=false`.

Certificate validation weakened:
- Node `saml2-js` / `passport-saml`: `cert: idpCert` accepted from config but `wantAssertionsSigned: false`, `disableRequestedAuthnContext`, or `audience` left empty/unchecked.
- `signatureAlgorithm` / `digestAlgorithm` downgraded to `rsa-sha1` / `sha1` (deprecated, collision-prone).
- Python `python3-saml` / `PySAML2`: `want_assertions_signed=False`, `want_assertions_encrypted=False`, `allow_unknown_attributes=True`, `certs` missing from `idp_data`.
- Ruby `ruby-saml`: `settings.security[:want_assertions_signed] = false`, `:metadata_signed` false, `:digest_method = XMLSecurity::SHA1`.

Lifecycle / replay gaps:
- `InResponseTo` checking off: OneLogin `settings.security[:reject_unsolicited_responses] = false`, OpenSAML `ReplayCache`/`InResponseTo` filter absent.
- `NotOnOrAfter` ignored: code only calls `isValid()` (sig) but never compares `sessionNotOnOrAfter` / `notOnOrAfter` to "now".
- RelayState misuse: `res.redirect(req.SAMLResponse.RelayState)` (open redirect), or `role = RelayState.split(':')[1]` (claim injection).

XML parsing / XXE:
- `DocumentBuilderFactory.newInstance()` without `setFeature(FEATURE_SECURE_PROCESSING, true)` / `setExpandEntityReferences(false)` / disallowing DOCTYPE.
- Go `encoding/xml` is XXE-safe by default but still comment/order-sensitive for XSW — confirm the library canonicalizes then verifies on the *exact* consumed subtree.
- PHP `SimpleSAMLphp`: `assertion.security.authnRequestsSigned` / `wantAssertionsSigned` false in `config/authsources.php`; `xml.disable_entity_loader` left on in older libxml.

## False positives
- The library performs C14N-then-verify on the same node it returns claims from (OpenSAML `validate` + `getAssertion` bound to the signed element; `passport-saml` with `wantAssertionsSigned` and audience/inResponseTo enabled). Confirm against docs, not just presence of a `validate()` call.
- IdP-initiated SSO is an intentional, documented design and the SP enforces Audience + Recipient + a replay cache for it.
- SHA-1 signatures appear only in a legacy IdP metadata element pinned for backward compatibility while default policy mandates SHA-256 — review the negotiated algorithm, not stale metadata.
- RelayState is a short opaque token echoed back, never used as a redirect target or claim source, and never reflected unencoded.

## Attack scenario
1. Attacker captures (or self-generates within a victim account) a valid signed `<samlp:Response>` containing a `<Signature>` over the legitimate `<Assertion>`.
2. The attacker clones the signed element and injects a **second, attacker-controlled** `<Assertion>` (or relocates the signed node into a wrapper) so the wrapped document is still schema-valid and the signature still verifies. This is the XSW variant family (XSW1–XSW4 differ in where the signed node is moved: sibling, child, external).
3. The vulnerable SP calls `verify()` against the signed node (pass) but then reads claims from the first node in document order — the attacker's node — yielding `NameID=victim`, `Role=admin`.
4. Alternatively, replay the exact captured assertion at the ACS endpoint from a new browser session; an SP lacking InResponseTo + one-time-use detection grants a fresh session.
5. Outcomes: full authentication as an arbitrary user (including the IdP administrator), lateral replay against another SP if Audience/Recipient are not enforced, or — if RelayState is reflected — an open redirect used to steal a freshly minted session token via a malicious domain.

## Impact
- **Confidentiality**: complete authentication bypass — the attacker becomes any user without credentials; all data the victim can reach is exposed.
- **Integrity**: actions performed, records created, or funds moved under the forged identity; privilege escalation if admin assertions are forgeable.
- **Availability**: account lockout / mass session invalidation via replay floods; IdP trust revocation can deny SSO to all federated apps.
- Severity is generally **Critical** when XSW or assertion forgery succeeds: it defeats the entire federated authentication boundary. Replay-only findings are High; missing Audience/Recipient is High when cross-SP assertion forwarding is feasible.

## Remediation
Use a maintained library in its strict configuration; verify the signature on the exact node you consume and enforce every lifecycle constraint:
```js
// passport-saml / @node-saml/passport-saml — STRICT config
const strategy = new SamlStrategy(
  {
    entryPoint: 'https://idp.example.com/sso',
    cert: process.env.IDP_CERT,                 // pinned IdP cert
    issuer: 'https://sp.example.com',           // == Audience / Recipient expected
    audience: 'https://sp.example.com',
    wantAssertionsSigned: true,                 // signature over the assertion
    signatureAlgorithm: 'sha256',               // NOT sha1
    digestAlgorithm: 'sha256',
    disableRequestedAuthnContext: false,
    acceptedClockSkewMs: 5 * 60 * 1000,         // 5 min, not hours
    // InResponseTo + replay cache are built in when a store is provided:
    //   - one-time-use enforcement via InResponseTo tracking
    validateInResponseTo: 'always',
  },
  (profile, done) => {
    // profile is derived from the SAME signed+validated node; do NOT re-parse the raw XML.
    if (profile.audience !== 'https://sp.example.com') return done(null, false);
    return done(null, profile);
  }
);
```
```js
// VULNERABLE — signature verified separately from the node consumed
const doc   = new DOMParser().parseFromString(rawResponse, 'text/xml');
const sig   = xmlCrypto.parseSignature(doc);          // covers Assertion #0
if (!sig.verify(idpCert)) return res.sendStatus(401);
const nameId = doc.getElementsByTagName('NameID')[0].textContent; // XSW: attacker's node
```
Defense-in-depth: pin IdP certificates and rotate via signed metadata, mandate SHA-256+ for both signing and digest, treat RelayState as opaque and never use it as a redirect target, and log assertion IDs in a short-lived replay cache so a captured assertion cannot be replayed even if a library bug is later found.

## References
- OWASP ASVS V2.x — Authentication and federation verification requirements
- OWASP WSTG-ATHN — Testing for Authentication, including SAML flows
- OWASP Cheat Sheet: SAML Security
