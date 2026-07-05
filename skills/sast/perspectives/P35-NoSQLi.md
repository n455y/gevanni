---
id: P35
name: NoSQLi
refs: ASVS V5.3.x / WSTG-INPV-05 / CS: NoSQL Injection, Query Parameterization
requires: [backend, db]
---

# P35 — NoSQLi

## Overview
NoSQL Injection (NoSQLi) occurs when user-controlled input is allowed to alter the **structure** of a NoSQL query rather than being treated as a bare value. In document stores such as MongoDB the vulnerability arises because query objects accept rich operator syntax (`$ne`, `$gt`, `$regex`, `$where`, `$in`); a request payload that deserializes into an object — not a string — can therefore inject conditions that bypass authentication, dump arbitrary documents, or trigger server-side JavaScript evaluation. The root cause is always the same: untrusted input reaches a query-construction path that does not coerce it to a primitive and does not restrict which operators may appear. The `$where` operator is an especially severe sub-case, since it evaluates a JavaScript expression on the database server, enabling RCE-adjacent data exfiltration and denial of service.

## What to check
- Does any query feed an object derived from the request (`req.body`, `req.query`, `req.params`) directly into `find`, `findOne`, `aggregate`, `updateOne`, `deleteOne`, or an ORM method (`Model.find(req.body)`)?
- Is the framework's query-string parser configured to expand nested objects/arrays (Express default `qs`, PHP nested `a[b]`, Go `gorilla/schema`)? A `?username[$ne]=1` then becomes `{ username: { $ne: '1' } }`.
- Is `$where` ever populated with a string, a concatenation, or any non-constant value? Confirm no `eval`-equivalent is reachable.
- Are comparison/logical operators (`$gt`, `$gte`, `$lt`, `$in`, `$nin`, `$exists`, `$regex`, `$ne`) accepted on fields that should hold scalar credentials (password, token, email, API key)?
- Are MongoDB URI connection strings or aggregation pipeline stages (`$match`, `$lookup`) built from user input?
- Does the app use `Content-Type: application/json` on auth/login endpoints where `body-parser`/`express.json()` returns an object without normalization?
- For Redis / Cassandra / Neo4j / Elasticsearch / GraphQL-backed stores, is a query/command string or template interpolated with raw input (Lua `EVAL`, CQL with string-building, Cypher concatenation, ES query-DSL field injection)?

## Static signals
Passing request objects straight to query APIs:
- `User.find(req.body)` / `User.findOne({ ...req.query })` / `Model.find(req.params)`
- `User.findOne({ email: req.body.email, password: req.body.password })` (object-typed `password` accepted)
- `collection.find({ $where: req.body.x })` / `db.eval(req.query.fn)`
- `User.find({ name: { $regex: req.body.q } })` (ReDoS + broad match)

String-built `$where` / server-side JS:
- `$where: 'this.' + col + ' == ' + val`
- `$where: \`this.user == '${req.body.u}'\``
- `db.collection(...).mapReduce(fn, ...)` with user-controlled `fn`

Drivers / ORMs across languages:
- Node: Mongoose `Model.find(req.body)`, `MongoClient` filter from spread objects `find({ ...req.query })`, `body-parser` returning objects
- Python: PyMongo `db.c.find(request.json)`, `find({"$where": request.args["q"]})`, MongoEngine `MyDoc.objects(**request.json)`
- Java: `collection.find(Document.parse(body))`, Spring Data `@Query("{ user : ?0 }")` with raw JSON, Morphia `DataService.find(query, body)`
- Go: `bson.M` built from `r.URL.Query()`, `q := bson.M{"user": r.FormValue("user")}` where value can be a map via `gorilla/schema`
- PHP: MongoDB PHP driver `$client->selectCollection()->find($_GET)`, Laravel MongoDB `User::where($_GET)->get()`
- Ruby: Mongoid `where(params[:filter])`, Mongo Ruby driver `collection.find(params[:q])`

## False positives
- Input is coerced to a primitive before querying: `String(req.body.email)`, `parseInt(req.body.id)`, or an explicit `typeof === 'string'` guard.
- A strict allow-list validator (Joi/Zod/JSON-schema with `additionalProperties: false`, Mongoose schema casting) rejects any field whose value is not a scalar, and an operator block-list (`$ne`, `$where`, `$regex` …) is applied.
- The query only interpolates server-generated, constant values; no request data touches the filter object.
- `$where` is not used at all, and operators are constructed through the driver's typed/bound builder rather than from parsed user objects.
- The store is a pure key-value engine (e.g. Redis `GET`/`SET` of opaque strings) with no string-interpolated `EVAL`/`KEYS` commands.

## Attack scenario
1. Attacker targets a JSON login endpoint that does `User.findOne({ email: req.body.email, password: req.body.password })`.
2. They send `Content-Type: application/json` with `{"email":"admin@x.com","password":{"$ne":null}}`.
3. The framework parses the body into an object; the query becomes `{ email: "admin@x.com", password: { $ne: null } }` — true for any non-null password — so `admin@x.com` is returned and authentication is bypassed.
4. Alternatively `{"username":{"$gt":""},"password":{"$gt":""}}` returns the first document in the collection, or `{"email":{"$regex":"^a"}}` enables blind enumeration / data extraction.
5. If `$where` is reachable, `{"$where":"sleep(5000)"}` times the response (boolean blind), or `{"$where":"this.password.match(/^a/) && sleep(5000)"}` exfiltrates the hash character by character and can hang the DB for DoS.

## Impact
- **Confidentiality**: full collection dumps, blind extraction of other users' credentials/tokens, authentication bypass on any account.
- **Integrity**: modify/delete via injected operators on update/delete endpoints; mass assignment of roles.
- **Availability**: `$where`/`$regex` (ReDoS) CPU exhaustion, `sleep()`-based locking, resource starvation on the database tier.
- Severity scales with the collection reached: an auth-bypass on a privileged account or `$where` on a multi-tenant cluster can become total compromise.

## Remediation
Normalize input to primitives and never feed request objects directly into a query:
```ts
// VULNERABLE — request object becomes the query filter
app.post('/login', (req, res) => {
  User.findOne({ email: req.body.email, password: req.body.password })
    .then(u => res.json({ ok: !!u }));
});
// Exploit: POST {"email":"admin@x.com","password":{"$ne":null}}

// SAFE — coerce to string + schema validation, no $where, bound operators
app.post('/login', (req, res) => {
  const { error, value } = loginSchema.validate({
    email: String(req.body.email ?? ''),
    password: String(req.body.password ?? '')
  });                       // Joi/Zod: type string, strip unknown keys
  if (error) return res.status(400).end();
  User.findOne({ email: value.email, password: value.password })
    .then(u => res.json({ ok: !!u }));
});
```
Apply defense-in-depth: block-list operators (`$where`, `$ne`, `$gt`, `$regex` …) at a middleware/DAO layer, prefer allow-listed field maps over `req.body` spreads, and never enable MongoDB server-side JavaScript (`javascriptEnabled: false`) in production.

## References
- OWASP ASVS V5.3.x — Input validation and injection prevention
- OWASP WSTG-INPV-05 — Testing for NoSQL Injection
- OWASP Cheat Sheets: NoSQL Injection Prevention, Query Parameterization, Injection Prevention
