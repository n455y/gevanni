---
id: P37
name: LDAPXPathInjection
area: V1 Encoding and Sanitization
refs: ASVS V5.3.x / WSTG-INPV-06, WSTG-INPV-10 / CS: LDAP Injection, Injection Prevention, XPATH Injection
requires: [backend, ldap]
---

# P37 — LDAPXPathInjection

## Overview
LDAP injection and XPath injection occur when user-controlled input is concatenated into an LDAP search filter or an XPath query string **without escaping or parameterization**. Both query languages are interpreted at runtime, and both treat metacharacters (`*`, `(`, `)`, `\`, `'`, `"`, `[`, `]`) as syntax, so an attacker who can reach those characters can reshape the query — bypassing authentication, widening a search to dump the directory, or extracting arbitrary XML nodes. The root cause is identical to SQL injection: untrusted data is fused into a command string rather than passed as a value. LDAP and XPath are less common than SQL, which makes them easy to overlook during code review and a frequent finding in directories that front SSO, address books, or config stores.

## What to check
- Is any user input (`req.body`, `req.query`, `req.params`, headers, cookies) concatenated into an LDAP filter string such as `(uid=<input>)`, `(mail=<input>)`, or `(cn=<input>*)`?
- Is user input concatenated into an XPath expression — `//user[name='<input>']`, `//*[@id='<input>']`?
- Are LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) and XPath metacharacters (`'`, `"`, `[`, `]`, `/`) escaped before interpolation?
- For LDAP binds, does the code build the **bind DN** from input (e.g. `uid=<input>,ou=people,dc=ex`) rather than using an anonymous search-then-bind or a parameterized DN lookup?
- Are wildcard searches (`(cn=<input>*)`) exposed such that `*` or `(objectclass=*)` from input returns the whole subtree?
- Does an authentication flow build its filter from the supplied username/password (`(&(uid=<u>)(userPassword=<p>))`)? This is a classic auth bypass (`*)(uid=*))(|(uid=*`).
- Is XPath evaluated against an XML store that holds secrets (config files, SAML metadata, user records)?
- Does the LDAP/XPath library in use support parameterized queries (variables, prepared statements), and is that feature actually used instead of string concatenation?

## Static signals
LDAP filter concatenation:
- Node: `client.search(base, \`(uid=${req.body.user})\`)`, `client.search(base, '(uid=' + u + ')')`
- Node: `ldap.authenticate(user, pass)` where the underlying lib composes `(&(uid=${user})(userPassword=${pass}))`
- Python: `conn.search('dc=ex', f'(uid={user})')`, `filterstr = "(cn=%s)" % name`
- Java: `ctx.search("uid=" + user + ",ou=people", ...)` (JNDI), `new SearchControls(...)`
- Go: `l.Search(req)` with `Filter: fmt.Sprintf("(uid=%s)", user)`
- PHP: `ldap_search($ds, $base, "(uid=$user)")`
- Ruby: `conn.search(base: base, filter: "(uid=#{user})")`

XPath concatenation:
- Node: `doc.select('//user[name=\'' + name + '\']')`, `xpath.evaluate(\`//item[@id='${req.params.id}']\`)`
- Python: `tree.xpath("//user[name='%s']" % name)`, `etree.XPath("//user[name='%s']" % name)`
- Java: `xpath.evaluate("//user[name='" + name + "']", doc)`
- Go: `xpath.MustCompile("//user[name='" + name + "']")`
- Ruby: `doc.xpath("//user[name='#{name}']")`

Absence of escape/bind:
- No call to `ldap.escape.filter(...)` / `ldapts` escaping before interpolation.
- Python: no `ldap.filter.escape_filter_chars(...)`, no raw-`@` parameter binding.
- XPath: no variable binding (`xpath.evaluate(expr, doc, {x: value})` in lxml, `XPathVariables` in Java), expressions built purely by `+` or f-strings.
- Direct wildcard from input: `(cn=${q}*)`, `contains(., '${q}')` where `q` may contain `*`.

## False positives
- LDAP input is escaped via `ldap.escape.filter()` (Node) / `escape_filter_chars` (Python) before interpolation, and the DN is built from a constant base plus a validated/escaped RDN.
- XPath uses parameterized variables (lxml variable map, Java `XPathVariableResolver`, .NET `XmlNamespaceManager.AddArgument`) so input never touches the expression text.
- Input was validated against a strict allow-list (UUID, numeric id, fixed enum) that cannot carry metacharacters.
- The LDAP/XPath store holds no sensitive data (e.g. a read-only public directory) and the endpoint enforces narrow search scope — impact is negligible.
- The application does not use LDAP or XPath at all (exclude during triage).

## Attack scenario
1. The login form POSTs `{user, password}` and the server builds `(&(uid=<user>)(userPassword=<password>))`.
2. Attacker submits username `*)(uid=*))(|(uid=*` with any password.
3. After substitution the filter becomes `(&(uid=*)(uid=*))(|(uid=*)(userPassword=...))`, which matches any user, so the bind succeeds and the attacker is logged in as the first directory entry (often an admin).
4. In a search endpoint `(cn=<q>*)`, submitting `(objectclass=*)` returns the entire directory — credentials, emails, groups — a full dump.
5. In XPath, submitting `'] | //user | //user[name='x` to `//user[name='<input>']` flattens the whole XML store, leaking config values or SAML signing keys.

## Impact
- **Confidentiality**: full directory/XML disclosure — accounts, emails, group membership, password hashes, secrets in XML config. Often the most severe outcome.
- **Integrity**: authentication bypass (logging in as another user), unauthorized privilege grants via directory group manipulation.
- **Availability**: wildcard `objectclass=*` queries can saturate the directory server (resource exhaustion / denial of service).
- Severity scales with what the store holds: an LDAP-backed SSO directory or an XML config with signing keys can mean complete application compromise.

## Remediation
Escape LDAP filter characters, or better, use a parameterized/bind API; for XPath, always bind variables:
```ts
// VULNERABLE — LDAP filter concatenation
const filter = `(uid=${req.body.user})`;
await client.search(base, { filter });

// SAFE — escape filter metacharacters
import { escapeFilter } from 'ldapts';
const filter = `(uid=${escapeFilter(req.body.user)})`;
await client.search(base, { filter });

// VULNERABLE — XPath concatenation
const node = doc.select(`//user[name='${req.params.name}']`);

// SAFE — parameterized XPath (lxml-style variable binding)
const node = doc.select('//user[name=$name]', { name: req.params.name });
```
For LDAP authentication prefer a fixed service DN that searches for the user, then binds with the user's supplied password (search-then-bind), and never interpolate raw input into the bind DN. Apply least-privilege directory accounts and limit search scope to a single OU as defense-in-depth.

## References
- OWASP ASVS V5.3.x — Input validation and injection prevention
- OWASP WSTG-INPV-06 — Testing for LDAP Injection
- OWASP WSTG-INPV-10 — Testing for XPath Injection
- OWASP Cheat Sheets: LDAP Injection Prevention, Injection Prevention, XPATH Injection Prevention
