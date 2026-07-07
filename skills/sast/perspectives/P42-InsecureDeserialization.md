---
id: P42
name: InsecureDeserialization
refs: ASVS V5.3.4 / WSTG-INPV-11 / CS: Deserialization, Insecure Deserialization
---

# P42 — Insecure Deserialization

## Preconditions

The code deserializes data from external sources.


## Overview
Insecure deserialization occurs when an application reconstructs objects from untrusted input using a native/general-purpose deserializer (`pickle`, `Marshal`, `ObjectInputStream`, `node-serialize`, PHP `unserialize`, .NET `BinaryFormatter`) that executes logic embedded in the byte stream or invokes magic lifecycle methods (`__reduce__`, `__wakeup`, `readObject`, `readResolve`). Unlike JSON, these formats carry type information and behavior, so the attacker controls not only the data but the *classes instantiated and the methods invoked*. The root cause is always the same: untrusted bytes reach a deserializer that was designed for trusted inter-process exchange, and the gadget chain assembled from reachable application/library classes runs with the application's privileges. Exploitation commonly yields remote code execution, making this one of the highest-severity injection classes.

## What to check
- Does any handler pass request-derived bytes (`req.body`, `req.cookies`, `req.headers`, uploaded file content, cache/queue messages) to a native/general-purpose deserializer instead of a data-only format parser?
- Is the deserializer itself safe by default? `pickle`, `marshal`, `phpggc`-targetable `unserialize`, `ObjectInputStream`, `XmlSerializer`/`BinaryFormatter`, `node-serialize` are **not**; `JSON.parse`, `yaml.safe_load`, Protocol Buffers are data-only.
- For YAML: is `yaml.load(stream)` used with the default unsafe loader instead of `yaml.safe_load`? `yaml.unsafe_load` / `Loader=FullLoader`-with-custom-tags also expand object graphs.
- Is a signed token (JWT, signed cookie) decoded and the resulting object's fields passed straight into a deserializer without re-validation?
- Are gadget-rich libraries on the classpath/runtime (Java: commons-collections, commons-beanutils, ROME, Hibernate; .NET: System.Workflow; Node: function-templating libs) that turn "I can deserialize" into "I get RCE"?
- Does the deserialized object's type get filtered by an allow-list (`resolveClass` override, `setObjectInputFilter`) or is it unrestricted?
- Is deserialization used on an inter-process channel (cache, message queue, RPC) where an attacker who can write to the channel (SSRF, poisoned cache) can inject a payload?

## Static signals
Python:
- `pickle.loads(req.body)`, `pickle.load(f)`, `cPickle.loads(...)`, `marshal.loads(...)`
- `yaml.load(s)` without `Loader=yaml.SafeLoader`, `yaml.unsafe_load(s)`, `yaml.full_load(s)`
- `shelve.open()`, `jsonpickle.decode()` over untrusted input

Node.js:
- `require('node-serialize').unserialize(req.body)` — RCE via `_$$ND_FUNC$$_` function bodies
- `serialize-js` `unserialize`, `funcsync`, custom `eval`-based revivers: `JSON.parse(s, (k,v) => eval(v))`
- `vm.runInThisContext` / `new Function` on decoded data

Java:
- `new ObjectInputStream(in).readObject()`, `XMLDecoder`, `XStream.fromXML` without `ALLOWED_TAGS`/`setupDefaultSecurity`, Jackson `enableDefaultTyping()` / `@JsonTypeInfo` on `Object`, Fastjson `autoType`, `XmlMapper`, `SerializationUtils.deserialize`
- JNDI lookups seeded by deserialized values: `InitialContext.lookup(user)`

PHP:
- `unserialize($_COOKIE[...])`, `unserialize($_POST[...])`, `unserialize(file_get_contents(...))`
- Custom `__wakeup` / `__destruct` classes reachable from the payload

Ruby:
- `Marshal.load(payload)`, `Oj.load(s, mode: :object)`, `YAML.load` (pre-3.1 unsafe)

.NET:
- `BinaryFormatter.Deserialize`, `JavaScriptSerializer.Deserialize` with a `SimpleTypeResolver`, `XmlSerializer` on attacker-controlled types, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`

Go:
- `gob.Decode` / `gob.NewDecoder` into `interface{}` with custom `GobEncoder` types; `encoding/gob` is lower-risk but flag `interface{}` targets

## False positives
- The input is parsed with a **data-only** format (`JSON.parse`, `yaml.safe_load`, `json.Unmarshal`, Protocol Buffers, MessagePack with fixed schema) and the resulting structure is validated against a strict schema before use.
- The bytes are cryptographically authenticated (signed/encrypted+MAC) with a key the attacker cannot forge, **and** the source is a trusted system; replay/algorithm-confusion still need separate review.
- The deserializer has an explicit type allow-list enforced (Jackson default typing with a `Validator`, `ObjectInputFilter` permit-list in Java 9+, XStream with `XStream.setupDefaultSecurity` + explicit `allowTypes`).
- The data is confined to primitive values and never drives a class loader or magic method (still risky in unsafe formats — confirm the format itself cannot embed type info).
- `unserialize` over a value that is constrained to an enum/allow-list of expected strings and never reaches a magic method.

## Attack scenario
1. Attacker probes an endpoint that accepts a `data` cookie decoded by `unserialize` (or a Java/RPC endpoint accepting a serialized blob).
2. Using `ysoserial` (Java) / `phpggc` (PHP) / a hand-built `pickle`/`node-serialize` payload, they craft an object graph whose construction (`readObject`, `__destruct`, `_$$ND_FUNC$$_`) executes a gadget chain ending in `Runtime.getRuntime().exec(...)`, `os.system(...)`, or a reverse shell.
3. The serialized payload is delivered via cookie, POST body, header, message queue, or a poisoned cache entry.
4. The application deserializes the blob, the gadget chain fires during reconstruction (before any business logic), and the attacker gains code execution as the application user — pivot to full host compromise.

## Impact
- **Confidentiality**: arbitrary file read, secret/credential exfiltration, full data dump.
- **Integrity**: arbitrary code execution → data tampering, backdoor planting, fraudulent state changes.
- **Availability**: process crash, resource exhaustion, ransomware-style destruction.
- Severity is typically **Critical** when an unsafe deserializer is reachable from untrusted input: RCE with the application's privileges. Scales down to High/Medium only when exploitation is gated behind authentication or a hard-to-reach channel.

## Remediation
Do not deserialize untrusted data with a native/general-purpose deserializer. Use a data-only format plus strict schema validation:
```ts
// VULNERABLE — general-purpose deserializer over request input
const serialize = require('node-serialize');
const obj = serialize.unserialize(req.body.data); // _$$ND_FUNC$$_ → RCE

// SAFE — data-only format + schema validation
const Parsed = z.object({ id: z.string().uuid(), n: z.number() });
const obj = Parsed.parse(JSON.parse(req.body.data));
```
If a native format cannot be avoided (legacy IPC), enforce a strict type allow-list (Java `ObjectInputFilter`, Jackson default-typing `Validator`, XStream `setupDefaultSecurity` + `allowTypesByWildcard`), authenticate and integrity-protect the stream, run deserialization in a low-privilege sandbox, monitor for gadget-chain libraries in dependencies, and log/alert on unexpected serialized types. Defense-in-depth: never place gadget-rich libraries on the runtime classpath of a service that deserializes external data.

## References
- ASVS V5.3.4
- WSTG-INPV-11
- CS: Deserialization, Insecure Deserialization
