---
id: P97
name: GraphQLComplexity
refs: ASVS V13.1.x / WSTG-INPV-13 / CS: GraphQL Cheat Sheet
---

# P97 — GraphQLComplexity

## Preconditions

The code exposes a GraphQL API.


## Overview
GraphQL APIs let the client shape the query: which fields, how deep, how many parallel fragments. This power is a denial-of-service vector when the server applies no ceiling on query depth, complexity, or cost. The three classic exploits are **deeply nested recursive queries** (a type that references itself can recurse a schema 100 levels deep), **alias/fragment batch amplification** (request the same expensive field 10,000 times via aliases in a single document), and **unbounded list fan-out** (a `users(first: 1000)` node each returning a `posts(first: 1000)` node → 1,000,000 resolvers). Root cause is always the same: an introspection-enabled endpoint accepting arbitrary client queries with no static-analysis gate (depth limit, cost analysis, persisted-query allowlist) before execution.

## What to check
- Is **any** depth/complexity/cost control applied before the query is executed (not after the resolvers run)?
- Is **query depth** bounded? A schema with a self-referential or cyclic type (e.g. `User → friends → User`) recurses as far as the client asks.
- Is **query cost** bounded via cost analysis (per-field directives like `@cost`, computed complexity, or a node-count limit)?
- Are **aliases** capped? `a1: field, a2: field, … a10000: field` runs the resolver N times in one request.
- Are **fragments** capped (fragment count, fragment depth, fragment spread into lists)?
- Are **list arguments** (`first`/`last`/`limit`) server-capped regardless of client input? Is `maxResults` enforced at the resolver/data-loader layer, not just trusted from the arg?
- Are **batched queries** (array of operations in one HTTP request) limited in count? Apollo batching allows thousands of ops per POST.
- Is **introspection** disabled in production (it leaks the schema so an attacker can hand-craft the worst query)?
- Is a **persisted-query / operation allowlist** in use, or does the server accept arbitrary query text from any client?
- Is there a per-request **wall-clock timeout** AND a resolver/concurrency limit? CPU work compounds inside a single query.
- Are mutations and subscriptions subject to the same limits (mutations trigger writes; an amplified mutation fans out side effects)?

## Static signals
No protection wired into the server (Node/Apollo):
- `new ApolloServer({ schema })` — no `validationRules`, no `plugins`
- `new ApolloServer({ typeDefs, resolvers })` — server created with no `validationRules: [depthLimit(...)]` / `complexity` plugin
- `import { graphqlHTTP }` (express-graphql) with `graphiql: true` and no depth limit
- Mercurius (Fastify) without `app.register(graphql, { ..., validationRules: [...] })`

List limits trusted from the client:
- `async users(parent, { first }, ctx) => ctx.db.user.findMany({ take: first })`
- Python (Strawberry/Ariadne/Graphene): `def users(self, first): return User.objects.all()[:first]`
- Java (GraphQL Java/kickstart): `@QueryMapping public List<User> users(@Argument Integer first)` with no `Math.min(first, MAX)` guard
- Go (gqlgen): `func (r *queryResolver) Users(ctx, first *int) → models.UserSlice` using `*first` directly
- Ruby (graphql-ruby): `field :users, [UserType], null: false do; argument :first, Integer; end` with no `prepare`/`max_page_size`

Missing persisted-query / allowlist plumbing:
- No `ApolloServerPluginCacheControl`, no `apollo-server-prepared-query` / operation-registry config
- No `allowlist` / `extractPersistedQueries` on `graphql-ruby`'s `Query`
- Introspection left on: `introspection: true` or simply unset in production; GraphiQL/Playground routes exposed

Recursive / self-referential types that make depth an amplifier:
- `type User { friends: [User] }`, `type Comment { replies: [Comment] }`, `type Node { children: [Node] }`

## False positives
- `graphql-depth-limit` AND a cost-analysis plugin (e.g. `graphql-cost-analysis`, `graphql-query-complexity`) are both registered in `validationRules`/`plugins`, AND list args are server-capped — well-defended.
- A persisted-query allowlist (operation allowlist / automatic persisted queries with a server-side registry) is in use and arbitrary query text is rejected (only stored operation hashes accepted) — the client cannot submit a crafted query.
- Introspection is disabled in production and a schema-aware gateway (not the field resolvers) enforces depth + cost before forwarding.
- A global query timeout plus a hard per-resolver concurrency/circuit-breaker limit caps blast radius even without formal cost analysis (defense-in-depth, though not a substitute).
- The schema has no cyclic/self-referential types AND no list fields, so the worst case is bounded by schema shape — still verify aliases are capped.

## Attack scenario
1. Attacker runs introspection (`{ __schema { types { name fields { name type { name kind ofType { name kind } } } } } }`) to map the schema — or just reads the published GraphiQL.
2. Identifies a self-referential list type, e.g. `User.friends: [User]`, and an unbounded list argument `users(first: Int)`.
3. Sends a single deeply nested query:
   ```graphql
   query { users(first: 100) { friends { friends { friends { friends { friends { id } } } } } } }
   ```
   Each level fans out 100× → 100^5 = 10,000,000,000 resolver calls / DB rows.
4. Variant — alias amplification without nesting: `{ a1: user(id:1){expensiveField} a2: user(id:1){expensiveField} ... a10000: ... }` runs the costly resolver 10,000 times in one HTTP POST.
5. One request saturates CPU and DB connections; legitimate requests queue and time out → DoS. Because it is a single small request, volumetric rate limits (req/s) do not catch it.

## Impact
- **Availability**: primary impact — full DoS via a single small request; the server spends CPU/RAM/DB connections on one query while legitimate clients starve. Cheap for the attacker, expensive for the server (asymmetry).
- **Confidentiality**: resolver errors triggered by oversized queries may leak internal field names, stack traces, or partial dataset fragments (especially with verbose error handling).
- **Integrity**: amplified mutations can fan out writes (mass record creation/update) before limits trip.
- Severity scales with the cheapest expensive resolver (a full-text search, an N+1 ORM call, or an upstream API hit) and whether introspection is exposed (drops the attacker's effort to near zero).

## Remediation
Apply depth limit + cost analysis at validation time AND cap list arguments at the resolver; reject arbitrary query text via persisted queries:
```ts
// VULNERABLE — no depth, cost, or alias limit; arbitrary queries accepted
import { ApolloServer } from '@apollo/server';
const server = new ApolloServer({ typeDefs, resolvers });

// SAFE — depth + cost + alias caps, introspection off, persisted queries
import depthLimit from 'graphql-depth-limit';
import costAnalysis from 'graphql-cost-analysis';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false,
  validationRules: [
    depthLimit(7),                                  // max nesting
    costAnalysis({ maximumCost: 1000, onComplete: c => c }), // computed complexity cap
  ],
  plugins: [/* persisted-query / operation-allowlist plugin */],
});

// resolver-level list cap — never trust the client arg
const MAX_PAGE = 50;
async function users(_, { first = MAX_PAGE }) {
  return db.user.findMany({ take: Math.min(first, MAX_PAGE) });
}
```
Layer defense-in-depth: disable introspection in production, enforce a per-request wall-clock timeout plus resolver concurrency limits, and front the endpoint with a persisted-query allowlist so only pre-approved operations are executable.

## References
- OWASP ASVS V13.1.x — Generic web service security, including GraphQL input/complexity controls
- OWASP WSTG-INPV-13 — Testing for GraphQL
- OWASP Cheat Sheet: GraphQL Security Cheat Sheet
