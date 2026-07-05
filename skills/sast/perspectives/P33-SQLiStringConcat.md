---
id: P33
name: SQLiStringConcat
refs: ASVS V5.3.x / WSTG-INPV-05 / CS: SQL Injection Prevention, Query Parameterization
requires: [backend, db]
---

# P33 — SQLiStringConcat

## Overview
SQL Injection via string concatenation occurs when request-controlled input is spliced into a SQL query string **instead of being passed through a parameterized interface** (prepared statement, bind variable, or ORM query builder). The root cause is always treating SQL as text to assemble rather than as a structure with typed parameters: a single `'`, `"`, `;`, or `--` from user input can break out of the intended literal and append, modify, or truncate the statement. The risk is highest where developers fall back to raw strings — dynamic `ORDER BY`/`LIMIT` clauses, dynamic table or column names, and legacy `query(...)` calls — because these constructs are awkward to parameterize. Even one concatenation point in an otherwise parameterized codebase is enough to compromise the database.

## What to check
- Does any handler interpolate request data (`req.query`, `req.params`, `req.body`, `req.headers`, path segments) into a SQL string literal via concatenation (`+`), template literals (`` ` ``), `sprintf`, `%`, or f-strings?
- Are raw query helpers used with string building — `db.query(...)`, `knex.raw(...)`, `sequelize.query(...)`, `cursor.execute(...)` with `%` formatting, JDBC `Statement` (not `PreparedStatement`), `db.Query()`/`db.Exec()` with `fmt.Sprintf`, PHP `mysqli_query`/`PDO::query` with concatenation?
- Are identifiers (column names, table names, `ORDER BY`/`GROUP BY` values, `LIMIT`/`OFFSET`) taken from user input? Identifiers **cannot** be parameterized with bind variables — they require a strict allow-list mapping.
- Is a `LIKE` clause being built by string concatenation? Special characters (`%`, `_`, `\`) must be escaped or the value must be bound (binding alone does not tame wildcards).
- Does server-side dynamic SQL (`EXECUTE`/`sp_executesql`, `EXECUTE IMMEDIATE`, PL/SQL) concatenate external input?
- Are validation/ORM convenience methods bypassed with raw fragments like `.where("name = '" + q + "'")` or `.havingRaw(...)`?
- Is the query logged or surfaced in error messages in a way that itself leaks structure (information disclosure adjacent to the SQLi)?

## Static signals
String concatenation / interpolation into SQL:
- Node/JS: `` db.query(`SELECT * FROM users WHERE id = ${req.params.id}`) ``, `'... WHERE name="' + q + '"'`
- Node/JS: `knex.raw('SELECT ... WHERE id = ' + id)`, `sequelize.query('... ' + q, { type: QueryTypes.SELECT })`
- Python: `cursor.execute(f"SELECT ... WHERE id = {pid}")`, `cursor.execute("... '%s'" % name)`, `cursor.execute("... " + q)` — only `cursor.execute("... %s", (name,))` is safe
- Java: `Statement stmt = conn.createStatement(); stmt.executeQuery("SELECT ... WHERE id = " + id)` — must be `PreparedStatement` with `?` binds
- Go: `db.Query("SELECT ... WHERE id = " + r.URL.Query().Get("id"))`, `fmt.Sprintf("... '%s'", q)` in a query — safe form is `db.Query("... WHERE id = $1", id)`
- PHP: `mysqli_query($conn, "SELECT ... WHERE id = " . $_GET['id'])`, `PDO::query("... " . $q)` — safe form is prepared statements with `?`/named placeholders
- Ruby: `User.where("name = '#{q}'")`, `ActiveRecord::Base.connection.execute("SELECT ... " + q)` — safe form is `User.where(name: q)` / parameterized `where("name = ?", q)`
- C#/.NET: `new SqlCommand("SELECT ... WHERE id = " + id, conn)` — safe form is `SqlParameter`

Dynamic identifiers (no allow-list):
- `ORDER BY ${req.query.sort}`, `LIMIT ${n}`, `SELECT ${column} FROM ...`
- `.orderBy(req.query.sort)` without validating against a known column set
- `db.query(\`SELECT ${fields} FROM ${table} WHERE ...\`)`

## False positives
- The query uses real bind parameters consistently: `?` placeholders, `$1`/`$2` positional, named `:id`/`@id`, ORM object form `.where({ col: val })`, `User.where(name: q)`, `cursor.execute("... WHERE id = %s", (pid,))`. Concatenation elsewhere in the file does not make these unsafe.
- An identifier (column/table/`ORDER BY` key) is selected from a hard-coded allow-list (`if (!ALLOWED_SORT.has(sort)) return 400`) — this is the correct pattern, not a finding.
- The interpolated value is a server-generated constant or enum resolved before reaching the query, never request data.
- The "query" is a NoSQL document filter or ORM condition object, not a raw SQL string (separate NoSQL-injection perspective applies).
- Integer input was validated/cast to a number (e.g. `parseInt`/`int(...)` with range check) before interpolation — lower risk, though parameterization is still preferred.

## Attack scenario
1. The application builds `db.query("SELECT * FROM products WHERE category = '" + req.query.cat + "'")`.
2. Attacker submits `cat=clothes' --` or `cat=clothes' OR '1'='1`, breaking out of the string literal.
3. The DB executes the modified statement — returning all rows, ignoring the intended filter, or appending a second statement (`'; DROP TABLE ...; --` where the API allows stacked queries).
4. To exfiltrate data the attacker uses a `UNION SELECT` to append columns from `users`, or an error-based / boolean-blind / time-based payload (`' AND SLEEP(5)--`) when results are not directly reflected.
5. With sufficient access the attacker reads credentials/hashes, writes a webshell via `INTO OUTFILE`, or pivots via `xp_cmdshell` / `COPY ... TO PROGRAM`.

## Impact
- **Confidentiality**: full read of database contents — credentials, PII, tokens, business data; often the DB contains data the app tier would never expose.
- **Integrity**: `UPDATE`/`INSERT`/`DELETE` through stacked or `UNION` payloads — fraudulent records, altered balances, admin account creation, tampered audit logs.
- **Availability**: `DROP TABLE`, destructive updates, or resource-exhausting queries that take the service down.
- Severity scales with DB privileges and DBMS features: a `sa`/root DB account with `xp_cmdshell`, `COPY TO PROGRAM`, or file-write access turns SQLi into remote code execution and full host compromise.

## Remediation
Always use parameterized queries; never build SQL by concatenating request data:
```ts
// VULNERABLE — string interpolation into SQL
app.get('/p', (req, res) => {
  db.query(`SELECT * FROM products WHERE category = '${req.query.cat}'`)
    .then(rows => res.json(rows));
});

// SAFE — bind parameter
app.get('/p', (req, res) => {
  db.query('SELECT * FROM products WHERE category = $1', [req.query.cat])
    .then(rows => res.json(rows));
});
```
For identifiers that cannot be bound (`ORDER BY`, column/table names), validate against a hard-coded allow-list and reject anything else. Apply **least-privilege DB accounts** (read-only where possible, no DDL/admin functions) and keep an allow-list/WAF rule as defense-in-depth — but parameterization is the primary control.

## References
- OWASP ASVS V5.3.x — Input validation and injection prevention (parameterized queries)
- OWASP WSTG-INPV-05 — Testing for SQL Injection
- OWASP Cheat Sheets: SQL Injection Prevention, Query Parameterization
