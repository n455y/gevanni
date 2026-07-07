---
id: P34
name: SQLiORM
refs: ASVS V5.3.x / WSTG-INPV-05 / CS: SQL Injection Prevention, Query Parameterization
---

# P34 — SQLiORM

## Preconditions

The code sends queries to a database.


## Overview
SQL injection through an ORM or query builder is the same classic flaw — untrusted data is allowed to alter the **structure** of a SQL statement, not just its data values — but it hides behind "we use an ORM, so we're safe." ORMs are only safe when their parameter-binding APIs are used; almost every ORM also exposes an escape hatch (`raw()`, `$queryRaw`, `execute`, `whereRaw`, string-built `where`) that, once fed concatenated or interpolated input, reopens the hole. A second, ORM-specific vector is **operator/mass-binding injection**: passing request-controlled objects straight into a `where` clause (`Model.find({ where: req.body })`) lets an attacker smuggle query operators such as `{$ne: null}`, `$gt`, or `$where` that bypass filters or trigger server-side JavaScript. The root cause is always treating user input as part of the query grammar rather than as a bound data value.

## What to check
- Does any ORM/query-builder call interpolate or concatenate request-derived data (`req.query`, `req.params`, `req.body`, `req.headers`) into a raw SQL string or a raw `where` clause?
- Is input passed directly as a query/filter object (`Model.find(req.body)`, `.where(req.body)`, `.filter(**request.json)`) without an allow-list of permitted keys/operators?
- Are column names, `ORDER BY` values, `LIMIT`/`OFFSET` sort keys, or table identifiers derived from input? Bind parameters protect **values** but cannot protect identifiers — these must be allow-listed.
- Are NoSQL/ORM operators (`$ne`, `$gt`, `$regex`, `$where`, `$expr`, `__raw__`) reachable through user-controllable keys because the framework did not have an allow-list / "sanitize" filter enabled?
- Is a raw query method invoked with `raw: true` or `type: sequelize.QueryTypes.RAW` and a template string rather than a bound parameter array?
- Are dynamic boolean/relational query builders (TypeORM `QueryBuilder.where("u.name = '" + name + "'")`, Django `extra(where=[...])` or `.raw()`, SQLAlchemy `text()` with `%`-formatting) fed concatenated strings?
- Does the app build `WHERE ... IN (...)` or `VALUES (...)` lists by joining an array into a string instead of using the ORM's array-expansion helper?

## Static signals
String concatenation/interpolation into raw SQL:
- Sequelize `.query(\`SELECT ... WHERE n='${name}'\`, { raw: true })` — missing bind array
- Knex `.raw(\`SELECT * FROM t WHERE n='${name}'\`)`, `.whereRaw(\`name='${name}'\`)`
- TypeORM `createQueryBuilder().where("u.name = '" + name + "'")` or `.where(\`u.name = ${name}\`)`
- Prisma `$queryRaw(\`SELECT * FROM "User" WHERE name='${name}'\`)` — must use `$queryRaw\`...${name}\`` tagged template
- SQLAlchemy `text("SELECT * FROM t WHERE n='" + name + "'")`, `session.execute(f"SELECT ... WHERE n='{name}'")`, `engine.execute("...%s..." % name)`
- Django `Model.objects.raw(f"SELECT ... WHERE n='{name}'")`, `.extra(where=[f"name='{name}'"])`
- Go: `db.Query(fmt.Sprintf("SELECT ... WHERE n='%s'", name))`; Ruby `User.where("name = '#{name}'")`
- Java/JPA: `em.createNativeQuery("SELECT ... WHERE n='" + name + "'")`; MyBatis `${param}` (concatenated) vs `#{param}` (bound)
- PHP: `DB::select(DB::raw("SELECT ... WHERE n='$name'"))` (Laravel), `mysqli_query($conn, "SELECT ... WHERE n='$name'")`

Mass-binding / operator injection (NoSQL or ORM filter objects):
- `User.find({ where: req.body })` (Sequelize), `User.find(req.body)` (TypeORM), `User.findOne(req.query)` (Mongoose)
- `Model.objects.filter(**request.json)` (Django ORM — ORM-level lookups like `password__isnull` reachable)
- `.whereRaw`, `.havingRaw`, Knex `.where({ ...req.body })`
- MongoDB operator keys (`$ne`, `$gt`, `$regex`, `$where`, `$or`, `$expr`) present in serialized query JSON without an allow-list

Identifier (column/table/sort) injection:
- `ORDER BY ${req.query.sort}`, `.orderByRaw(req.query.order)`, dynamic `SELECT ${col}` without allow-list
- `knex(req.params.table).select(...)` — table name taken from input

## False positives
- Parameterized raw calls with explicit bind arrays/values: `knex.raw('SELECT * FROM t WHERE n = ?', [name])`, `sequelize.query('... WHERE n = :n', { replacements: { n: name } })`, Prisma tagged template `$queryRaw\`...WHERE n = ${name}\``, SQLAlchemy `text('... WHERE n = :n').bindparams(n=name)`, MyBatis `#{param}`.
- Filter objects built from a validated schema / explicit allow-list of keys, with disallowed operators stripped (e.g. Mongoose `sanitizeFilter`, Express-validator allow-list, a DTO that only exposes permitted fields).
- Identifier values (column/table/sort) matched against a hard-coded allow-list before insertion (`if sort not in ['name','created_at']`) — only allow-listed identifiers are safe.
- The "input" is a server-generated constant or a typed enum value, not request data.
- ORM find-by-id with a coerced integer (`Model.find(parseInt(req.params.id))`) where no raw clause is involved.

## Attack scenario
1. The app exposes a search endpoint and builds the raw filter by concatenation: `knex.raw(\`SELECT * FROM users WHERE name='${req.query.name}'\`)`.
2. Attacker sends `?name=admin'--` to short-circuit the rest of the clause, or `?name=' UNION SELECT username,password,3 FROM accounts-- -` to pull a different table.
3. Because the string is spliced into the SQL grammar, the database executes the attacker-controlled statement, returning other users' password hashes.
4. Operator variant: an endpoint does `User.find({ where: req.body })`; the attacker POSTs `{"username":"admin","password":{"$ne":null}}` (or `{"password":{"$gt":""}}`), logging in as the first account whose password is not null — full authentication bypass.

## Impact
- **Confidentiality**: full read of any table — credentials, PII, secrets, other tenants' data.
- **Integrity**: `INSERT`/`UPDATE`/`DELETE` via stacked or `UNION` queries, account/role tampering.
- **Availability**: `DROP`, mass-delete, or expensive queries causing downtime; on some DBs, command execution (`xp_cmdshell`, `COPY FROM PROGRAM`, UDFs) reaches the OS.
- Severity scales with DB privileges: a read-only app account caps blast radius; an admin/`sa` connection can mean total host compromise.

## Remediation
Use bound parameters for values and an allow-list for identifiers and filter keys:
```ts
// VULNERABLE — interpolation into raw SQL
const rows = await knex.raw(`SELECT * FROM users WHERE name='${req.query.name}'`);

// SAFE — bound parameter
const rows = await knex.raw('SELECT * FROM users WHERE name = ?', [req.query.name]);

// VULNERABLE — operator / mass-binding injection
const user = await User.findOne({ where: req.body });

// SAFE — allow-list of permitted fields, primitives only
const ALLOWED = ['username', 'email'];
const filter = pick(req.body, ALLOWED);       // drop unknown keys
const user   = await User.findOne({ where: filter });
```
As defense-in-depth, run the app against the database with least-privilege grants (no DDL, no cross-table reads), enable the ORM's operator-sanitization filter, and prefer the query-builder API over raw SQL whenever it can express the query.

## References
- OWASP ASVS V5.3.x — Input validation and injection prevention
- OWASP WSTG-INPV-05 — Testing for SQL Injection
- OWASP Cheat Sheets: SQL Injection Prevention, Query Parameterization, NoSQL Injection Prevention
