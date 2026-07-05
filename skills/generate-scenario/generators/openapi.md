# OpenAPI Scenario Generator

Generate gevanni-compatible `x-gevanni-scenarios` entries for OpenAPI specs.

## Arguments

- `$ARGUMENTS`: Path to the source code directory or file to analyze. If omitted, analyze the current working directory.

## Workflow

### Step 1: Discover project context

1. Find existing OpenAPI spec files (`.openapi.yaml`, `.openapi.yml`, `.openapi.json`) in the project root and `.gevanni/scenarios/` directory.
2. Read any existing spec to understand defined operations.
3. Read the source code at the path given in `$ARGUMENTS` to discover HTTP endpoints.

### Step 2: Analyze source code for HTTP endpoints

Scan the source code for route definitions. Look for patterns across common frameworks:

- **Express/Connect/Koa**: `app.get`, `app.post`, `router.put`, `router.delete`, etc.
- **Fastify**: `fastify.get`, `fastify.post`, `fastify.route`, etc.
- **Hono**: `app.get`, `app.post`, `router.use`, etc.
- **Next.js**: Files under `pages/api/` or `app/api/` with exported handlers.
- **NestJS**: `@Get()`, `@Post()`, `@Put()`, `@Delete()`, `@Patch()` decorators in controllers.
- **Spring Boot (Java/Kotlin)**: `@GetMapping`, `@PostMapping`, `@RequestMapping`, etc.
- **Django/Flask/FastAPI (Python)**: `@app.route`, `@router.get`, `def get_*`, function-based views.

For each endpoint, extract:

- **HTTP method** (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
- **URL path** (with path parameters like `{id}`)
- **Parameters**: query, path, header, cookie
- **Request body**: JSON schema structure, content type, oneOf/allOf patterns
- **Response structure**: especially any links to other operations
- **Authentication requirements**: headers, cookies, tokens

### Step 3: Analyze for vulnerability classes and required test data

Scan the source code for known vulnerability patterns and classify each endpoint:

**SQL Injection (SQLi)** — endpoints with string-concatenated SQL:

- `sequelize.query(` / `db.query(` / `knex.raw(` — raw query execution
- `db.sequelize.query(` / `models.sequelize.query(` — Sequelize raw query
- String interpolation in SQL strings (`SELECT * FROM ${table}`)
- Look for `req.query`, `req.params`, `req.body` being directly interpolated into SQL

**NoSQL Injection** — endpoints using `$where` or raw NoSQL operators:

- `$where:` in MongoDB queries — JavaScript expression injection
- `db.collection.find({ $where:` — raw JavaScript evaluation
- String concatenation of user input into `$where` expressions

**Reflected / Stored XSS** — endpoints that echo user input in responses:

- User input (`req.body.*`, `req.query.*`, `req.params.*`) reflected in response body
- Input stored in database then shown to users without sanitization
- Look for `.insert(` / `.save(` followed by `.find(` that returns the stored data

**Path Traversal / LFR / File disclosure** — endpoints with file-system access using user input:

- `fs.readFile(` / `path.resolve(` / `res.sendFile(` using `req.params.*` or `req.query.*`
- `express.static(` over user-controllable directories
- `serveIndex(` / `servePublicFiles(` / `serveQuarantineFiles(` / `serveKeyFiles(` / `serveLogFiles(` — directory listing + file download endpoints (commonly mounted at `/ftp/:file`, `/support/logs/:file`, `/encryptionkeys/:file`, `/.well-known/:file`). These expose a **path parameter** that is prime target for path traversal payloads (`../../etc/passwd`, `%00` null byte bypass). **Always add these to `paths`** with the file name as a `path` parameter.
- Template render with user-controlled layout/path (`res.render(req.body.layout)`) — Local File Read (LFR)

**Other classes**: XXE (XML parsing), OS Command Injection (`exec`, `spawn`), SSTI (template engines with user input), LDAP/XPath injection, Open Redirect (`res.redirect(req.query.*)`), SSRF (`fetch(req.body.url)` / `axios(req.body.*)`), RCE (`vm.runInContext(` / `eval(` with user input), Business Logic (role escalation, price/coupon manipulation)

**Identify required dynamic test data**:

While analyzing endpoints, identify any fields that require specific test data values to test the functionality:

- **Discount/coupon codes**: Fields like `couponCode`, `discountCode`, `promoCode` — the actual codes must be provided by the user
- **Invitation/referral codes**: Fields like `inviteCode`, `referralCode` — actual codes must be provided
- **Test account identifiers**: Fields like `accountId`, `customerId` when testing multi-tenant systems — actual IDs must be provided
- **Application-specific codes**: Any other domain-specific codes or identifiers needed for testing

**⚠️ Do NOT invent these values.** Document them in a list to be confirmed with the user in Step 5.

**Record for each endpoint**:

- Vulnerability class(es) it is susceptible to
- The exact parameter(s) involved (query name, body field, path param)
- Code snippet (file:line) for reference

### Step 4: Path parameter and type audit

While building the operation list, check for gevanni limitations:

1. **Path parameters** (`in: path`): gevanni's default parser plugins (query, json, form, header, cookie, graphql) do **not** scan URL path segments. Path parameters in OpenAPI definitions will **not** be automatically audited by signatures. To scan them:
   - Ensure the `parser:path` / `mutation:path` plugins are registered in `builtin.ts`
   - Or, alternatively, **duplicate the path parameter as a query parameter** in the OpenAPI spec (add `in: query` with the same name) so the `parser:query` plugin picks it up
   - Log a **warning** when path parameters are present: "⚠️ Path parameter `{name}` in `{operationId}` will not be scanned unless PathParserPlugin is enabled. Consider adding a duplicated query parameter."

2. **Integer-typed path parameters**: When a path parameter has `type: integer`, AppendValue-mutation signatures (most SQLi/NoSQLi/XSS) will break the URL by appending a string to a numeric segment (e.g. `/rest/products/1' OR 1=1--/reviews`). The server often returns 404 or an empty result.
   - **Recommendation**: Change `type: integer` → `type: string` and set `example: "1"` (a valid numeric value) so that AppendValue produces valid injection URLs while the server still parses the ID correctly (Express/Node treats path params as strings by default).
   - Log a **warning**: "⚠️ Integer path parameter `{name}` in `{operationId}` — change type to string with example for injection to work."

3. **BearerAuth / security requirements**: gevanni resolves authentication **inside the scenarios** from `securitySchemes`. A scenario's token-returning step (e.g. `login`) yields the token, and gevanni injects it into every later `security: bearerAuth` operation as `Authorization: Bearer <token>` — automatically. No `Authorization` header parameter and no OpenAPI Link are needed; the `Authorization` header is excluded from audit so signatures never mutate it. Credentials and the login flow live entirely in the spec; the scan script only sets `proxy:http.upstream` and must NOT inject tokens globally.
   - **Identify the login operation** that returns a token (e.g. `POST /rest/user/login`)
   - **Ask the user for credentials**: "What username/email and password should be used for the login operation `{operationId}`?"
   - **Do NOT invent** test credentials like `test@example.com` / `password123`
   - Declare the scheme in `components/securitySchemes` and point gevanni at the token field with `x-gevanni-token`:
     ```yaml
     components:
       securitySchemes:
         bearerAuth:
           type: http
           scheme: bearer
           x-gevanni-token: $response.body#/authentication/token # JSON pointer to the token in the login response
     ```
   - `x-gevanni-token` is a runtime expression evaluated against each step's response; the first step whose response yields a value (e.g. `login`) becomes the token source. Works for `http:bearer` and `oauth2` (→ `Authorization: Bearer <token>`) and `apiKey` with `in: header` (→ the configured header).
   - Define the token-returning operation (e.g. `POST /rest/user/login`) with credentials in its requestBody `example`.
   - Tag protected operations with `security: bearerAuth` (standard OpenAPI). **Do not** add an `Authorization` header parameter.
   - Make each protected scenario start with the token step: `steps: [login, <auth-op>]`.
   - Log an **info** message: "💡 `{operationId}` requires bearerAuth — covered by a `[login, {operationId}]` scenario; gevanni injects the JWT via `securitySchemes` (`x-gevanni-token`)."

4. **CAPTCHA or other bot protection**: If source code references CAPTCHA (`captcha`, `captchaId` fields, captcha verification middleware), those endpoints cannot be scanned automatically. Log: "⚠️ `{operationId}` appears to require CAPTCHA — automated scanning not possible."

### Step 5: Confirm required parameters with the user

Before proceeding to spec generation, confirm all required runtime parameters that cannot be extracted from the code or from prior responses via OpenAPI Links.

**A. Target server base URL:**

1. **Check configuration files** for hints about the server URL:
   - `.env` / `.env.local` / `.env.development` — look for `BASE_URL`, `API_URL`, `HOST`, `PORT`, `SERVER_URL`
   - `config.js` / `config.ts` / `application.yml` / `application.properties` — look for server/port config
   - `package.json` — check `scripts.dev` or `scripts.start` for port hints
   - Docker files (`Dockerfile`, `docker-compose.yml`) — check exposed ports
2. **Ask the user**: "What is the base URL of the target web server? (e.g., `http://localhost:3000`, `https://staging.example.com`)"
3. **Wait for user input** — do not proceed without an actual URL
4. **Store the provided URL** in the spec's `servers` list

Example interaction:
```
🌐 Target server base URL needed:

The generated OpenAPI spec needs a `servers` URL. Based on the codebase:
  • Found .env with PORT=3000 → possible URL: http://localhost:3000

Please confirm or provide the correct base URL for the target server:
```

If the codebase has hints, present them as suggestions but **always require user confirmation**. Do not auto-populate.

**B. Authentication credentials:**

For each token-returning operation (typically `login`, `authenticate`, `signIn`):

1. **Ask the user**: "What credentials should be used for the `{operationId}` operation? (e.g., username/email, password)"
2. **Wait for user input** — do not proceed without actual values
3. **Use the provided values** in the `requestBody.example` field when generating the operation

Example interaction:
```
🔐 Credentials needed for scenario generation:

The following operations require authentication data:
  • login (POST /rest/user/login) — needs username and password
  • adminLogin (POST /admin/auth) — needs admin username and password

Please provide the credentials to use:
```

**C. Dynamic test data:**

For each field requiring application-specific codes or identifiers:

1. **Present the list** to the user with context (endpoint, parameter name, purpose)
2. **Ask for actual values** — do not invent placeholder codes
3. **Wait for user input** before proceeding

Example interaction:
```
📋 Test data needed for scenario generation:

The following endpoints require specific test data:
  • applyDiscount (POST /rest/coupon/apply) — needs a valid couponCode
  • acceptInvite (POST /rest/invitations/accept) — needs a valid inviteCode
  • getTenant (GET /rest/tenants/{id}) — needs a valid tenant ID for testing

Please provide the actual values to use in the generated scenarios:
```

**D. Parameter extraction via OpenAPI Links (DO NOT ask user):**

Parameters that can be extracted from previous step responses should **NOT** be asked from the user — define these using OpenAPI Links instead:

- **User/Resource IDs returned by create operations**: Use `$response.body#/id` in the next step's path/query/body
- **Order/Transaction IDs**: Use `$response.body#/orderId` in tracking/status operations
- **Session tokens returned by login**: Use `$response.body#/token` via `securitySchemes.x-gevanni-token`
- **Any field in a prior response**: Use `$response.body#/field.name` runtime expression

These are automatically resolved by gevanni at runtime — no user input needed.

**E. Proceed only after confirmation:**

- Do NOT proceed to Step 3 until all required credentials and test data have been provided
- If the user cannot provide certain values (e.g., valid coupon codes), mark the corresponding operations as `scannable: false` and note the reason

### Step 6: Build or update the OpenAPI spec

#### operationId is MANDATORY for every operation

**Every operation (every method+path combination) MUST have a unique `operationId`.** gevanni resolves scenarios by `operationId` only — an operation without `operationId` is **invisible to the scanner** and will never be audited. This is the single most common cause of missing coverage.

Rules:

1. **One operationId per method+path.** A path with multiple methods (e.g. `GET /api/Users` + `POST /api/Users`) needs a **distinct** operationId for each method. Never share or omit.
2. **Naming convention**: `<verb><Resource>` — `listUsers` (GET collection), `createUser` (POST), `getUserById` (GET item), `updateUser` (PUT), `deleteUser` (DELETE), `searchProducts`, `trackOrder`, `uploadFile`, `b2bOrder`, etc. Verbs: `get/list/create/add/update/replace/delete/remove/search/track/verify/submit/apply/upload/download/serve`.
3. **Globally unique.** No two operations may share an operationId.
4. **Derived from behavior, not just path.** `GET /rest/wallet/balance` → `getWalletBalance`; `PUT /rest/wallet/balance` → `addWalletBalance`. Not both `walletBalance`.
5. When adding an endpoint from Step 2 whose path already exists in the spec (e.g. file-serving `/ftp/{file}`), add it as a **new path entry** with its own operationId — do not skip it.

#### If no spec exists

Create a new OpenAPI 3.0 spec at `.gevanni/scenarios/openapi.yaml` with:

- `openapi: "3.0.0"`
- `info.title` and `info.version`
- `servers` with the base URL
- `paths` with all discovered operations — **each with a unique operationId** (see rules above)
- `x-gevanni-scenarios` section

Ensure the `.gevanni/scenarios/` directory exists before writing the spec.

#### If a spec already exists

- Check `.gevanni/scenarios/openapi.yaml` for existing spec
- Preserve all existing content
- Add missing operations to `paths`
- Add missing scenarios to `x-gevanni-scenarios`
- Do not remove or modify existing scenarios unless the user asks
- Write the updated spec to `.gevanni/scenarios/openapi.yaml`

### Step 7: Coverage planning — ensure every scannable operation has a scenario

This is a **mandatory validation step** before finalizing the spec. The goal is to maximize vulnerability detection coverage.

**A. Build a coverage matrix**

List every `operationId` in `paths` and mark each with:

| Column       | Description                                                           |
| ------------ | --------------------------------------------------------------------- |
| operationId  | Unique operation identifier                                           |
| auth         | `no-auth` / `bearerAuth` / `cookie`                                   |
| params       | Parameter types present (`query`, `path`, `body`, `header`, `cookie`) |
| vuln classes | From Step 2b: `sqli`, `nosqli`, `xss`, `pathtraversal`, `xxe`, etc.   |
| has scenario | ✅ or ❌                                                              |
| scenario id  | The `x-gevanni-scenarios` id that covers this operation               |
| scannable    | Is automated scanning feasible?                                       |

**B. Prioritize uncovered operations for scenario creation**

Priority order (highest first):

1. **No-auth + injection-vulnerable** (sqli, nosqli, xss, xxe, command-injection)
   - These are the **highest value** — can be detected without authentication
   - Create a single-step scenario with `diff: exact` (not json!)
   - Example: `searchProducts`, `trackOrder`

2. **No-auth + other vulnerability** (pathtraversal, idor, ssrf)
   - Single-step scenario
   - Diff strategy depends on response type

3. **BearerAuth + any vulnerability**
   - **Scan via a `[login, <op>]` scenario**: `securitySchemes.x-gevanni-token` captures the JWT from `login` and gevanni injects `Authorization: Bearer <token>` into the operation automatically (see Step 2c-3). No header parameter or Link needed.
   - `diff: exact` for injection-vulnerable endpoints, `json` for read-only endpoints with dynamic responses

4. **No-auth + no known vulnerability**
   - Create a single-step scenario for completeness
   - Diff strategy can be `json` if responses carry dynamic values

5. **CAPTCHA-protected / TOTP-required endpoints**
   - Mark `scannable: false` — automated scanning is not possible
   - Emit warning

**C. Coverage target**

The final spec must have:

- ✅ At least one scenario per **no-auth** operation (unless explicitly marked unscannable)
- ✅ Every **injection-vulnerable** operation (Step 2b) has a scenario with `diff: exact`
- ✅ BearerAuth operations are covered by a `[login, <op>]` scenario; gevanni injects the JWT via `securitySchemes` (`x-gevanni-token`)
- ❌ CAPTCHA/TOTP operations are marked `scannable: false`

**D. Output the coverage summary** before proceeding to Step 4. This makes gaps visible and ensures nothing is accidentally skipped.

### Step 8: Generate x-gevanni-scenarios

Follow these rules when generating scenarios:

**⚠️ CRITICAL: Use user-provided values in operation examples:**

When defining operations in the OpenAPI spec, use the **actual values provided by the user in Step 5** for:
- `requestBody.example` fields (credentials, coupon codes, invite codes, etc.)
- `parameters.example` values (test IDs, specific identifiers, etc.)

**Do NOT invent placeholder values** like:
- ❌ `test@example.com`, `admin@example.com`, `user@example.com`
- ❌ `password123`, `admin123`, `testpass`
- ❌ `DISCOUNT20`, `SAVE10`, `PROMO2024`
- ❌ `12345`, `test-id-123`, `sample-tenant`

These invented values will likely fail at runtime and produce false negatives.

#### Basic scenarios

Create one scenario per operation. Use `operationId` as both the scenario `id` and step reference:

```yaml
x-gevanni-scenarios:
  - id: listUsers
    steps:
      - listUsers
  - id: createUser
    steps:
      - createUser
```

#### Authenticated endpoint scenarios (JWT via securitySchemes)

For operations with `security: bearerAuth`, authentication is resolved **inside the scenario** from `securitySchemes`. gevanni captures the token from the token-returning step's response (`x-gevanni-token`) and injects `Authorization: Bearer <token>` into every later `security: bearerAuth` step — automatically, and excluded from audit. The scan script injects **nothing** — it only sets `proxy:http.upstream`.

Setup (done once in the spec):

1. Declare the scheme with `x-gevanni-token` pointing at the token field:
   ```yaml
   components:
     securitySchemes:
       bearerAuth:
         type: http
         scheme: bearer
         x-gevanni-token: $response.body#/authentication/token
   ```
2. Define the token-returning operation (e.g. `POST /rest/user/login`) with credentials in its requestBody `example`.
   - **⚠️ CRITICAL: Ask the user for actual credentials** — do not invent values like `test@example.com`, `password123`, or `admin/admin`.
   - Query the user: "What username/email and password should be used for the login operation in the generated scenarios?"
   - Use the provided values in the `requestBody.example` field
3. Tag protected operations with `security: bearerAuth` (standard OpenAPI). Do **not** add an `Authorization` header parameter.

Then every authenticated scenario starts with the token step:

```yaml
x-gevanni-scenarios:
  - id: createProductReview # injection-vulnerable → exact
    steps:
      - login
      - createProductReview
    diff:
      strategy: exact

  - id: getBasket # read-only with dynamic responses → json
    steps:
      - login
      - getBasket
    diff:
      strategy: json
```

gevanni evaluates `x-gevanni-token` against each step's response; once captured, the token is injected into all subsequent `security: bearerAuth` steps. `oauth2` schemes work the same way (`x-gevanni-token: $response.body#/access_token`); `apiKey` (`in: header`) injects into the configured header. Multi-step chains beyond the leading token step are only needed when operations are genuinely chained (e.g. create-then-read).

**⚠️ Use user-provided credentials**: The `requestBody.example` for the `login` operation must use the **actual credentials provided by the user in Step 5**, not invented placeholders.

#### Multi-step flows

When operations are chained (e.g., create resource then get it by ID), create multi-step scenarios.

**Use OpenAPI Links for data extraction:**

When a parameter can be extracted from a prior operation's response, define it using OpenAPI Links — do **not** hardcode values or ask the user for them.

```yaml
x-gevanni-scenarios:
  - id: createUserAndGet
    steps:
      - createUser
      - getUserById  # ID extracted via $response.body#/id Link
```

**OpenAPI Links mechanism:**

Define Links in the operation's response to pass data to subsequent operations:

```yaml
paths:
  /users:
    post:
      operationId: createUser
      responses:
        "201":
          description: User created
          links:
            getUserById:
              operationId: getUserById
              parameters:
                id: "$response.body#/id"  # Extract ID from createUser response
```

**Runtime expressions supported:**
- `$response.body#/json/pointer` — Extract from JSON response body
- `$response.header#/header-name` — Extract from response headers

**When to use user-provided static values vs Links:**

| Scenario | Approach | Example |
|----------|----------|---------|
| Resource ID returned by create operation | **OpenAPI Link** | `$response.body#/id` in next step |
| Authentication token from login | **securitySchemes + Link** | `x-gevanni-token: $response.body#/token` |
| Discount/coupon code to apply | **User-provided value** | Use code from Step 5 in `requestBody.example` |
| Invitation code to accept invite | **User-provided value** | Use code from Step 5 in `requestBody.example` |
| Test account ID for multi-tenant testing | **User-provided value** | Use ID from Step 5 in path parameter example |

**Rule of thumb:**
- If the value can be **extracted from a prior response** → Use OpenAPI Links
- If the value must be **provided externally** (coupon code, invite code, test credentials) → Ask user in Step 5, use provided value in `example`

#### oneOf variants

When a request body uses `oneOf`, create separate scenarios using `match`:

```yaml
x-gevanni-scenarios:
  - id: notifyEmail
    steps:
      - id: sendNotification
        match: { channel: email }
  - id: notifySms
    steps:
      - id: sendNotification
        match: { channel: sms }
```

The `match` value must correspond to an enum value or const in the variant schema. For variants without a discriminant, use a numeric index:

```yaml
- id: variant0
  steps:
    - id: createItem
      match: 0
```

#### Scenario composition with sub-scenarios

When multiple scenarios share a common prefix, extract it as a reusable sub-scenario:

```yaml
x-gevanni-scenarios:
  - id: getUuidPart
    steps:
      - getUuid
  - id: uuidInBody
    steps:
      - getUuidPart
      - useUuidInBody
  - id: uuidAsQuery
    steps:
      - getUuidPart
      - useUuidAsQuery
```

#### Second-order scenarios

When a primary flow has alternate downstream branches from the same seed operation:

```yaml
x-gevanni-scenarios:
  - id: uuidInBody
    steps:
      - getUuidPart
      - useUuidInBody
    secondOrders:
      - steps:
          - getUuid
          - useUuidAsQuery
```

#### Non-scannable helpers

Sub-scenarios that only serve as reusable building blocks should be marked `scannable: false`:

```yaml
- id: loginPart
  steps:
    - login
  scannable: false
```

#### Diff strategy

Set `diff` to control how response differences are detected when a signature replays a true/false pair (e.g. boolean-based SQL injection sends `' AND 1=1--` vs `' AND 1=2--` and flags the operation as vulnerable when the responses differ).

- `exact` (default) — raw byte comparison of response body plus status code. Produces false positives when responses carry dynamic values (timestamps, random IDs, counters).
- `json` — compares the normalized JSON _structure_ (keys and types), **ignoring values** and key order. Use this for JSON APIs where dynamic values would cause noise. Only active for `application/json` responses; non-JSON responses are treated as identical.
- `html` — strips `<script>`/`<style>`, removes attribute values, and collapses whitespace before comparing. Use this for HTML endpoints. Only active for `text/html` responses; non-HTML responses are treated as identical.

**⚠️ Critical: Do NOT use `json` strategy for injection-vulnerable endpoints.** The `json` diff strategy normalizes away all _values_ and only compares structure (keys, types). Boolean/diff-based signatures (sqli-boolean, sqli-diff, nosql-boolean, nosql-diff) rely on value-level differences (e.g. true payload returns data, false payload returns empty) to detect vulnerabilities. With `json` strategy, both responses normalize to identical empty structures, producing **false negatives** — real vulnerabilities go undetected.

**Diff strategy selection guidelines:**

| Scenario type                     | Recommended strategy   | Reason                                              |
| --------------------------------- | ---------------------- | --------------------------------------------------- |
| SQLi / NoSQLi suspected (Step 2b) | `exact`                | boolean/diff signatures need value-level comparison |
| GET with no injection risk        | `json` or omit (exact) | safe default                                        |
| Multi-step login flows            | `exact`                | token exchange differences need value comparison    |
| HTML endpoints                    | `html`                 | strip dynamic scripts/styles before comparison      |

```yaml
# ✅ CORRECT: injection-vulnerable endpoint with exact diff
- id: searchProducts
  steps:
    - searchProducts
  diff:
    strategy: exact

# ❌ WRONG: injection endpoint with json diff — will miss boolean/diff detections
- id: searchProducts
  steps:
    - searchProducts
  diff:
    strategy: json
```

Omit `diff` to use the default `exact` strategy.

### Step 9: Verify scenario transition integrity

Before final validation, verify that every generated scenario can correctly navigate from step to step at runtime. A scenario with broken transitions will fail silently at scan time — this step catches those failures at generation time.

**A. Step reference resolution**

For every scenario in `x-gevanni-scenarios`:

1. Confirm each step references a valid target:
   - **Direct operationId** (string like `searchProducts`): must exist in `paths`
   - **Object step** (`{id, match}`): `id` must exist in `paths`
   - **Sub-scenario reference** (step name matching another scenario's `id`): the referenced scenario must exist in `x-gevanni-scenarios`
2. Emit an **error** for any unresolved step reference:
   ```
   ❌ Scenario `{scenarioId}` step `{stepRef}`: operationId not found in paths.
   ```

**B. Parameter satisfaction check for multi-step flows**

For each step in a multi-step scenario, verify all `required` parameters can be resolved at runtime. A parameter is "satisfied" if at least one of the following holds:

| Source | How it resolves |
|--------|----------------|
| **OpenAPI Link from prior step** | A prior step's response defines a Link targeting this operationId with the parameter mapped |
| **Runtime expression** | The parameter's `example` or `schema.example` uses `$response.body#/...` or `$response.header#/...` referencing a prior step |
| **Static example value** | The parameter or its schema has an `example` in the operation definition |
| **Auth injection** | The parameter is an auth header/token injected by gevanni via `securitySchemes` (`x-gevanni-token`) |
| **Optional parameter** | The parameter is not listed in the operation's `required` array |

For each **unsatisfied required parameter**, emit a **warning**:
```
⚠️ Scenario `{scenarioId}` step `{stepOpId}`: required parameter `{paramName}` (in: {paramIn}) has no resolvable source.
   → Add an example value, a Link from a prior step, or mark it optional if not needed.
```

When checking prior-step Links, resolve runtime expressions against the prior operation's response schema. If a Link maps `$response.body#/authentication/token` but the prior operation's response schema has no `authentication.token` path, emit a **warning**:
```
⚠️ Scenario `{scenarioId}`: Link from `{sourceOpId}` → `{targetOpId}` references `$response.body#/authentication/token`, but `{sourceOpId}` response schema has no such field.
```

**C. Link target and field cross-validation**

For every Link defined in operation responses:

1. **Target exists**: The Link's `operationId` must exist in `paths`. Missing → **error**.
2. **Parameter mapping validity**: Each mapped parameter must exist in the target operation's parameter list (path/query/header/cookie). Mapped-to-nonexistent-param → **error**.
3. **Runtime expression plausibility**: `$response.body#/...` expressions should reference paths that exist in the source operation's response schema. Unverifiable (no response schema defined) → **warning** with a hint to add one.

```
❌ Scenario `{scenarioId}`: Link from `{sourceOpId}` → `{targetOpId}` maps parameter `{paramName}`, but `{targetOpId}` has no such parameter.
```

**D. Token flow validation for bearerAuth scenarios**

For every scenario whose steps include `security: bearerAuth` operations:

1. A token-returning step (login, authenticate, signIn, etc.) must appear **before** any protected step
2. The token-returning operation must have `x-gevanni-token` declared in `components/securitySchemes` pointing to the token field in its response
3. The scenario's `steps` array must list the token step first: `[tokenStep, protectedStep, ...]`

Emit an **error** if a protected step has no preceding token step:
```
❌ Scenario `{scenarioId}`: step `{protectedOpId}` requires bearerAuth but no token-returning step precedes it.
   → Add a login/authenticate step before the protected operation.
```

Emit a **warning** if the token step exists but the scheme is missing `x-gevanni-token`:
```
⚠️ Scenario `{scenarioId}`: `{tokenOpId}` provides auth but `components/securitySchemes/bearerAuth` is missing `x-gevanni-token`.
   → Add `x-gevanni-token: $response.body#/path.to.token` to the security scheme.
```

**E. Circular dependency detection in sub-scenarios**

Sub-scenario references form a directed graph. Detect cycles to prevent infinite loops at runtime:

1. Build the graph: scenario `A` → sub-scenario `B` for every step in `A` that references another scenario's `id`
2. Run DFS from each scenario; a back-edge indicates a cycle
3. Emit an **error** for every cycle, listing the scenario ids in the loop:
   ```
   ❌ Circular sub-scenario dependency detected: {scenarioA} → {scenarioB} → {scenarioA}
   ```

**F. Transition integrity summary**

After all checks, output a summary:

```
🔗 Scenario transition integrity:
   • Scenarios checked:    N
   • Multi-step scenarios: N
   • Total step transitions: N
   • ✅ Valid transitions:   N
   • ⚠️ Warnings:            N
   • ❌ Errors:              N
```

If errors exist, the generated spec must be fixed before use. If only warnings exist, review them and decide whether to add examples or Links.

**G. Runtime transition verification (actual HTTP requests)**

After the static checks pass, verify that scenarios can actually navigate by sending real HTTP requests through the scenario plugin's execution logic. This catches issues that static analysis cannot: DNS failures, TLS errors, routing mismatches, authentication redirects, and unexpected response shapes that break Link resolution.

**Prerequisites:**
- The target server must be running and reachable at the base URL from Step 5
- If the server is not running, skip this section and emit a note: "⚠️ Target server not available — skipping runtime transition verification."

**Procedure:**

1. Run the validation script against the generated spec:
   ```bash
   gevanni validate-scenarios .gevanni/scenarios/openapi.yaml
   ```
   If the user provided a different base URL than what's in the spec, pass `--base-url`:
   ```bash
   gevanni validate-scenarios .gevanni/scenarios/openapi.yaml --base-url http://localhost:3000
   ```

2. The script executes every scenario by:
   - Building the HTTP request for each step (URL, headers, body) using the same `buildUrl`/`buildHeaders`/`buildBody` functions the scenario plugin uses
   - Sending the request to the target server
   - Extracting tokens via `securitySchemes.x-gevanni-token` (same as `executeSteps`)
   - Resolving Link parameters via `$response.body#/...` and `$response.header#/...` (same runtime expression resolver)
   - Passing resolved values as overrides to the next step (same inter-step data flow)

3. For each step, the script reports:
   - ✅ Success: HTTP status code received (e.g., `GET /rest/products/search → 200`)
   - ❌ Failure: error details (connection refused, timeout, DNS failure, etc.)
   - 🔗 Link resolution: whether each `$response.body#/...` expression resolved to a non-empty value

4. **Interpret the output:**
   - **All steps ✅ and all Links 🔗 resolved**: transitions are valid — proceed to Step 10
   - **Some steps ❌**: the scenario cannot navigate — fix the spec (wrong path, missing parameter, unreachable server) and re-run
   - **Steps ✅ but Links 🔗 unresolved**: the server responded but the response shape doesn't match the Link expressions — verify the `$response.body#/...` paths against the actual response JSON
   - **4xx/5xx status codes are NOT failures**: a 401 without auth or a 422 with a test value is normal during validation — only connection-level failures (ECONNREFUSED, timeout, DNS) count as transition errors

5. **Example output:**
   ```
   🔗 Validating scenario transitions...

   📄 Spec: /workspace/.gevanni/scenarios/openapi.yaml
   🌐 Base URL override: http://localhost:3000

   📋 Found 5 scenario(s)

   ▶ Running: searchProducts
     ✅ GET /rest/products/search?q=test → 200

   ▶ Running: loginAndGetBasket
     ✅ POST /rest/user/login → 200
        🔗 Link → getBasket.token: eyJhbGciOiJIUzI1NiIs...
     ✅ GET /rest/basket/{id} → 200

   ═══════════════════════════════════════
   🔗 Scenario transition integrity:
      • Scenarios checked:     5
      • Multi-step scenarios:  2
      • Total step executions: 7
      • ✅ Successful steps:   7
      • ❌ Failed steps:       0
      • 🔗 Links checked:      2
      • ✅ Resolved links:     2
      • ⚠️  Unresolved links:   0
   ═══════════════════════════════════════

   ✅ All scenario transitions are valid.
   ```

6. **On failure**, analyze the output and fix the spec before re-running:
   - Connection failures → check the `servers[0].url` in the spec
   - 404 on a path → check the operation's `path` template (path parameters replaced with defaults?)
   - Unresolved Link → the prior step's response doesn't contain the field at the JSON Pointer path; either fix the pointer or check if the response shape differs in reality

7. **Re-run after fixes**: if you modified the spec to fix transition errors, re-run the validation script to confirm the fix.

### Step 10: Validate

Check the generated output:

1. Every `operationId` referenced in `x-gevanni-scenarios` exists in `paths`
2. Every `match` criterion corresponds to a valid `oneOf` variant
3. Runtime expressions (`$response.body#/...`) reference fields in response schemas
4. No duplicate scenario `id` values
5. The YAML is syntactically valid
6. The spec has `openapi: "3.x.x"`
7. `diff.strategy` (when set) is one of `exact`, `json`, `html`
8. **Path parameter warnings**: For every operation that defines `in: path` parameters, emit a warning that these will not be scanned by the default parser plugins. Suggest duplicating as query parameters or ensuring `parser:path` / `mutation:path` plugins are registered.
9. **Integer path parameter check**: For any path parameter with `type: integer`, warn that injection signatures using AppendValue will break the URL. Suggest changing to `type: string` with `example: "<valid integer>"`.
10. **Diff strategy vs vulnerability class**: For every scenario where Step 2b identified SQLi or NoSQLi risk, verify the diff strategy is **not** `json`. If it is, emit an **error** and force `exact`. This is the most common cause of false negatives.
11. **BearerAuth without token flow**: For every operation with `security: bearerAuth`, verify (a) the scheme is declared in `components/securitySchemes` with `x-gevanni-token`, (b) a scenario reaches it via a token-returning step (e.g. `[login, <op>]`), and (c) no `Authorization` header parameter was added (gevanni injects it from the scheme). Emit a warning if any are missing.
12. **CAPTCHA endpoints**: If Step 2b flagged CAPTCHA requirements, mark the scenario `scannable: false` and emit a warning.
13. **operationId presence (CRITICAL)**: Iterate every method+path in `paths` and assert each operation has an `operationId`. Any operation missing `operationId` is an **error** — it cannot be referenced by a scenario and will never be scanned. List all offenders and assign one before finishing.
14. **operationId uniqueness (CRITICAL)**: Collect all operationIds; if any duplicate exists, emit an **error** and rename (especially for multi-method paths sharing a name).
15. **Full coverage check (CRITICAL)**: Compute `defined_operationIds − scenario_referenced_operationIds`. Every operationId not referenced by some scenario is a **gap**. Emit each as `❌ <operationId> not covered`. The only acceptable uncovered operations are those explicitly marked `scannable: false` (CAPTCHA/TOTP). Iterate until the gap list is empty or all remaining are justified.
16. **Multi-method path coverage**: For paths with multiple methods (GET+POST, GET+PUT, etc.), confirm **each method's** operationId has its own scenario. A single scenario cannot cover two operations on the same path.

Run tests if available:

```bash
npx vitest run src/plugins/loader/openapi-loader.test.ts
```

## Reference: x-gevanni-scenarios schema

```yaml
x-gevanni-scenarios:
  - id: string                           # Required: unique scenario identifier
    steps:                                # Required: ordered list of steps
      - string                            # Simple: just an operationId
      |                                   # OR
      - id: string                        # Step with variant selection
        match:                            # For oneOf bodies
          { key: value }                  # Object match on enum/const
          | number                        # Index match
          | [{ key: value }, ...]         # Merge multiple variants
    diff:                                 # Optional: response diff strategy
      strategy: exact | json | html       # Required when diff is set (default: exact)
    secondOrders:                         # Optional: alternate request chains
      - steps:                            # Same format as main steps
          - string | { id: ..., match: ... }
    scannable: boolean                    # Optional: defaults to true
```

## Reference: OpenAPI Links (response-level)

OpenAPI Links in responses define data flow between operations. gevanni uses these to resolve runtime expressions:

```yaml
responses:
  "200":
    links:
      NextOp:
        operationId: nextOp
        parameters:
          id: "$response.body#/id" # Pass response field as a path/query/header parameter
        requestBody:
          token: "$response.body#/token" # Pass response field in body
```

Supported runtime expressions:

- `$response.body#/json/pointer` - Extract from JSON response body
- `$response.header#/header-name` - Extract from response headers
