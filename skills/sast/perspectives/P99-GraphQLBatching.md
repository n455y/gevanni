---
id: P99
name: GraphQLBatching
area: V4 API and Web Service
refs: ASVS V13.x / WSTG-ATHN-04 / CS: GraphQL Cheat Sheet
---

# P99 — GraphQLBatching

## Overview
GraphQL query batching and aliasing let a client submit many operations (or many invocations of the same field) inside a single HTTP request. The protocol also allows one mutation/operation to be repeated dozens of times via aliases. This collapses the usual 1-request = 1-action assumption that rate limiters, account-lockout, and brute-force defenses rely on. The root cause is not in the GraphQL spec itself but in the absence of per-operation and per-field cost controls: an attacker can fire hundreds of `login(user, password)` attempts — each with a different candidate password — as one batched request that the server treats as a single transaction and that a naive IP-based rate limiter counts as one hit. Without a batch-size cap, query-depth/complexity limit, or authentication-specific throttle, the same primitive enables credential stuffing, data exfiltration via nested aliases, and resource-exhaustion DoS.

## What to check
- Is **query batching** enabled by default (Apollo, Yoga, Mercurius, Ariadne, Sangria, graphql-java) without a maximum number of operations per request?
- Are **aliases** permitted? Aliases let one query call the same field N times (e.g. N `login` calls in one document) — does any cost/depth analysis count them?
- Do authentication / credential-handling fields (`login`, `signIn`, `authenticate`, `requestPasswordReset`, OTP verify, 2FA) have a **separate, stricter rate limit and account-lockout** that is applied **per operation inside a batch**, not once per HTTP request?
- Is there a **query cost / complexity limit** (depth, complexity, recursion, leaf count) enforced before execution? Default Apollo has none.
- Are **persisted / automatic persisted queries (APQ)** enforced on sensitive mutations? If APQ is global, a raw un-persisted document can still be sent to bypass the persisted-query gate.
- Does the gateway enforce limits even when individual resolvers are cheap (a cheap `login` resolver is still a slow password hash check = CPU amplifier)?
- Is the batch executed as one transaction such that a partial failure does not abort remaining operations (Apollo `extraBatchHandlingOpts` / `parallelism`)?
- Are introspection and `__schema` reachable inside a batch to enumerate the auth surface?
- Does the same pattern apply over WebSocket / SSE subscriptions (graphql-ws, subscriptions-transport-ws), where batching occurs across frames?

## Static signals
Batching enabled without size cap:
- `ApolloServer({ schema })` with no `validationRules` (Node/Apollo)
- `import { ApolloServerPluginCacheControl } ...` present but **no** `costAnalysis` / `depthLimit` / `createComplexityRule`
- `gateway.loaders`, `Bottleneck`, `express-rate-limit` keyed on `req.ip` only — counts a 100-op batch as 1
- Yoga / Pothos: `createYoga({ schema })` without `parserOptions.maxTokens` / cost plugin

Missing per-operation auth throttle:
- resolver calls `authenticate(...)` / `bcrypt.compare(...)` / `argon2.verify(...)` directly, with no middleware/decorator rate-limiting the field
- `@auth` / `@rateLimit` directives absent on `Mutation.login` while present on data resolvers
- Pinia/Express: `app.use('/graphql', limiter)` with `windowMs`/`max` but no per-document walk

Aliased brute force signature (the request body itself is the signal):
- `a0: login(...)`, `a1: login(...)`, `a2: login(...)` in the same `query` string
- `mutation { a:login{...} b:login{...} ... z:login{...} }`

Multi-framework grep:
- Node: `graphql-depth-limit`, `graphql-cost-analysis`, `graphql-query-complexity`, `@escapetechnology/graphql-armor` absent from `validationRules`
- Python (Strawberry/Ariadne/Graphene): `from strawberry.extensions import ...` without `MaxAliasesLimiter` / `DepthLimiter` / `ValidationRulesExtension`
- Java (graphql-java / Spring for GraphQL): `GraphQL.newGraphQL(schema).build()` with no `Instrumentation` cost rules, no `MaxQueryDepthInstrumentation`, no `MaxQueryComplexityInstrumentation`; Spring `BatchLoaderRegistry` unbounded
- Go (gqlgen): `handler.NewDefaultServer(generated.NewExecutableSchema(...))` with no `extension.ApolloTracing`/complexity; `gqlgen` complexity config unset defaults to 0 = unlimited
- Ruby (graphql-ruby): `MySchema.max_depth` / `MySchema.max_complexity` not set; `GraphQL::Batch` used without batch size cap
- PHP (webonyx/graphql-php / Lighthouse): `GraphQL\Server\ServerConfig` without `validationRules` / complexity; Lighthouse `@cache` on resolvers but no `@guard`-rate on auth
- .NET (HotChocolate / GraphQL.NET): `services.AddGraphQLServer().AddQueryType<...>()` without `.ModifyCostOptions` / `.MaxExecutionDepth`

## False positives
- A **batch size cap** (e.g. Apollo `batching: { limit: 10 }` / Yoga `parserOptions` / graphql-armor `maxTokens`) **plus** a per-operation complexity/depth rule **plus** a field-level rate limiter on auth mutations is in place — batched auth brute force is then bounded.
- Authentication resolvers are **excluded from batching** by design (separate non-batchable endpoint, or the server rejects batches containing auth operations) — the design is sound.
- The API only accepts **persisted query IDs** for mutations and rejects raw documents, removing the attacker's ability to inject aliased brute-force queries.
- Rate limiting is correctly applied **per operation** (the gateway expands the batch and counts each op) rather than per HTTP request.
- A WAF / edge layer enforces a low maximum request body size and per-IP request count that makes large batches infeasible (verify it counts operations, not just bytes).

## Attack scenario
1. Attacker registers a list of 10,000 candidate passwords from a breached-credential dump.
2. Instead of 10,000 HTTP requests (which the IP rate limiter would block), they build a single GraphQL batch of, say, 500 aliased `login` mutations, each carrying the same username and one password candidate:
   ```
   mutation {
     a0: login(input:{username:"victim", password:"123456"}){ token }
     a1: login(input:{username:"victim", password:"password"}){ token }
     ...
     a499: login(input:{username:"victim", password:"qwerty99"}){ token }
   }
   ```
3. The server executes all 500 in one request. The IP limiter records one hit; the account-lockout counter (if tied to failed HTTP requests) advances by one or not at all.
4. The attacker repeats with 20 requests, covering all 10,000 candidates. One alias returns a `token`; the attacker reads it out of the batch response.
5. The same primitive works for 2FA OTP brute force (1000 aliased `verifyOtp` calls = 1000 guesses per request), coupon/voucher enumeration, and data exfiltration via deeply aliased nested reads that bypass the rate limiter and amplify server load (each alias re-runs resolvers / DB joins).

## Impact
- **Confidentiality**: full account takeover via batched credential stuffing; mass data extraction through aliased nested queries that bypass per-request data caps.
- **Integrity**: actions taken as the compromised user (funds transfer, config change); OTP/coupon/lock-bypass via aliased guessing.
- **Availability**: deeply nested or aliased queries create a CPU/memory amplifier (one cheap-to-parse request triggers thousands of resolver/DB calls) — classic GraphQL DoS.
- Severity scales steeply with what the brute-forced field protects: a `login` batch without lockout is critical; a read-only public field with cost limits is informational.

## Remediation
Cap batch size, enforce cost/depth, and rate-limit auth operations **per operation**:
```ts
// VULNERABLE — no batch limit, no cost rule, login brute-forceable via aliases
import { ApolloServer } from '@apollo/server';
const server = new ApolloServer({ schema });
// limiter elsewhere is keyed on req.ip → counts a 500-op batch as 1

// SAFE — depth + complexity + per-operation auth throttle + batch cap
import depthLimit from 'graphql-depth-limit';
import costAnalysis from 'graphql-cost-analysis';
import { ApolloArmor } from '@escapetechnology/graphql-armor';

const armor = new ApolloArmor({
  maxAliases: { n: 5 },        // block aliased brute force
  maxTokens: { n: 1000 },
  maxDepth: { n: 7 },
  maxDirectives: { n: 50 },
  costLimit: { maxCost: 1000 },
});

const server = new ApolloServer({
  schema,
  validationRules: [depthLimit(7), costAnalysis({ maximumCost: 1000 }),
                    ...armor.apollo.inlinePlugins()],
  // auth mutations get a field-level limiter (1 attempt / IP / 10s) in context
});
```
Also: disable batching for auth operations entirely if possible, require persisted-query IDs for mutations, set per-field `@rateLimit` on `login`/`verifyOtp`/`requestPasswordReset`, and lock the account after N **operation-level** failures (not request-level). Defense-in-depth: enforce a maximum request body size and a depth/cost limit at the edge (WAF/API gateway) so the policy holds even if the app server is misconfigured.

## References
- OWASP ASVS V13 (API & Web Service) — input validation, resource consumption, anti-automation controls
- OWASP WSTG-ATHN-04 — Testing for Bypassing Authentication Schema (brute force / rate-limit bypass)
- OWASP Cheat Sheet: GraphQL Security Cheat Sheet (batching, aliasing, query cost analysis, persisted queries)
