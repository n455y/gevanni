---
id: P96
name: GraphQLIntrospection
area: V4 API and Web Service
refs: ASVS V13.x / WSTG-INPV-13 / CS: GraphQL Cheat Sheet, GraphQL (Apollo)
requires: [backend, graphql]
---

# P96 — GraphQLIntrospection

## Overview
GraphQL introspection is a built-in query mechanism (`__schema`, `__type`) that exposes the entire API schema — types, fields, arguments, mutations, subscriptions, and deprecation hints — to any client that asks. In production this is an information-disclosure goldmine: attackers reconstruct the full attack surface without source access, uncover hidden admin mutations, and target deprecated but still-live fields. The same class of issue covers interactive IDEs (GraphiQL, Apollo Sandbox, GraphQL Playground) left enabled in prod, which combine introspection with a query console. Root cause is always a configuration default left untouched — Apollo, graphql-yoga, and most servers enable introspection by default, so shipping without an explicit `NODE_ENV==='production'` guard leaks the schema.

## What to check
- Is GraphQL introspection enabled in production? Confirm both the server config (`introspection: true` or unset-default) and a live `query { __schema { types { name fields { name } } } }` probe against the `/graphql` endpoint.
- Is an interactive IDE (GraphiQL, Apollo Sandbox, GraphQL Playground, Altair) reachable in production? Look for `graphiql: true`, `playground: true`, `endpoint: '/graphql'` served on the same host.
- Is the dev/debug configuration (`NODE_ENV !== 'production'` gate) correctly wired so it actually disables both introspection and the IDE in the prod build? Verify the env var is set where the server actually runs (container, serverless, reverse proxy).
- Are `__schema` / `__type` queries rejected before field resolution, or only after the schema is partly serialized? A custom `validationRules` allow-list that filters introspection late can still leak type names in errors.
- Does the API rely on "security through obscurity" (field name guessing) rather than authorization checks on each resolver? Introspection defeats obscurity entirely.
- Are persisted queries / allow-listing in use? If so, introspection should still be disabled — the allow-list is the control, not schema secrecy, but introspection nonetheless aids denial-of-service via deep-query crafting.
- Is query depth/complexity limiting configured? Even with introspection off, leaked schema lets attackers craft expensive nested queries (see P97 — GraphQLDoS).

## Static signals
Apollo Server (Node):
- `new ApolloServer({ introspection: true })`
- `new ApolloServer({ schema, playground: true, introspection: true })` (v2/v3)
- `ApolloServer({ graphiql: true })`
- Missing `introspection` key with no `NODE_ENV` guard (default = enabled)

Express-graphql / graphql-http:
- `graphqlHTTP({ schema, graphiql: true })`
- `graphqlHTTP({ schema, introspection: true })`

graphql-yoga / mercurius / Pylon:
- `createYoga({ schema, graphiql: true })` (Yoga enables Playground by default)
- `app.register(mercurius, { graphiql: true, introspection: true })`

Python (Graphene / Strawberry / Ariadne / graphql-core):
- `GraphQLView.as_view(graphiql=True)`
- `Strawberry(... )` served via ASGI without `introspection=False` middleware
- Custom `ValidationRule` that fails to block `IntrospectionQuery`

Java (graphql-java / Spring for GraphQL / Netflix DGS):
- `GraphQLSchema` served via `graphql-java` without `Instrumentation` disabling introspection
- Spring for GraphQL: `spring.graphql.graphiql.enabled=true` in `application-prod.properties`
- `graphiql` static resources shipped in the prod JAR

Go (gqlgen):
- `handler.NewDefaultServer(executableSchema)` (GraphiQL enabled by default)
- `gqlgen` config without `introspection: false`

Ruby (graphql-ruby):
- `MySchema = GraphQL::Schema.new` mounted with `GraphiQL::Rails` in production routes
- `GraphQL::Schema.to_definition` exposed via an endpoint

PHP (webonyx/graphql-php / Lighthouse / OverblogGraphQLBundle):
- `StandardServer([ 'schema' => $schema ])` (introspection on by default)
- Lighthouse `graphql.introspection=true` in `lighthouse.php`
- Overblog bundle `overblog_graphql.devmode=true` in prod

Generic / framework-agnostic:
- `__schema` or `__type` strings present in non-test source (custom handlers)
- Routes serving `/graphiql`, `/playground`, `/sandbox`, `/altair`, `/voyager` in prod
- `if (NODE_ENV === 'development')` wrapping IDE but not introspection (asymmetric leak)

## False positives
- Staging/dev environments where introspection and IDEs are intentionally enabled — confirm the host is genuinely non-prod (subdomain, env var, separate deployment) and not reachable from the public internet.
- Introspection is disabled AND no IDE is mounted — then the only residual risk is field-name enumeration via error messages (separate, lower-severity finding).
- Authenticated-only introspection design where only admin roles can introspect — still a Medium finding per ASVS (defense-in-depth: schema should not be a privilege), but acceptable if explicitly documented as an admin tool.
- Persisted-queries-only mode where arbitrary queries are rejected; introspection is moot because the introspection query itself is blocked at the gateway even if the schema flag is on.
- The `__schema`/`__type` strings appear only in test fixtures or in the schema-definition `.graphql` files used at build time (not a runtime leak).

## Attack scenario
1. Attacker discovers a GraphQL endpoint via content-type sniffing, JS bundle references, or common paths (`/graphql`, `/api/graphql`, `/v1/graphql`).
2. Attacker sends `POST /graphql` with `{"query":"{ __schema { queryType { name } mutationType { name } types { name fields { name type { name } args { name } } } } }"}`.
3. The server returns the complete schema, revealing an undocumented `adminDeleteUser` mutation, a deprecated `legacySsn` field on the `User` type, and the `Subscription` root with a `paymentReceived` topic.
4. Attacker crafts authenticated queries/mutations against the hidden surface, bypassing the assumption that "undocumented = inaccessible."
5. If a GraphiQL/Playground is also exposed, the attacker gets an in-browser console with autocomplete to iterate the exploitation without any local tooling.

## Impact
- **Confidentiality**: full disclosure of the API attack surface, hidden types, deprecated fields, internal naming, and argument shapes — accelerates every other vulnerability class (auth bypass, IDOR, injection).
- **Integrity**: enables targeted abuse of dangerous mutations uncovered through the schema dump.
- **Availability**: leaked schema makes it trivial to craft deeply nested, high-cost queries for resource-exhaustion DoS.
- Severity is Medium baseline (information disclosure); it escalates to High when combined with broken authorization on a discovered mutation, or when an interactive IDE is exposed in production.

## Remediation
Disable introspection and interactive IDEs in production; gate them behind the environment explicitly:
```ts
// VULNERABLE — prod leaks schema + Playground
const server = new ApolloServer({ schema, introspection: true, playground: true });

// SAFE — introspection and IDE only in non-prod
const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== 'production',
  playground: process.env.NODE_ENV !== 'production',
});
```
For graphql-java use an introspection-disabling `Instrumentation`/`GraphQLCodeRegistry`; for Python use a `ValidationRule` that rejects `IntrospectionQuery` in prod. As defense-in-depth, enforce per-resolver authorization (never rely on field secrecy) and add query depth/complexity limits so even a leaked schema cannot yield a DoS amplifier.

## References
- OWASP ASVS V13.x — API and Web Service protection, GraphQL controls
- OWASP WSTG-INPV-13 — Testing for GraphQL injection / introspection
- OWASP Cheat Sheets: GraphQL Cheat Sheet, GraphQL (Apollo) Security
