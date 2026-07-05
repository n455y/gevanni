---
id: P98
name: GraphQLBOLA
area: V4 API and Web Service
refs: ASVS V4.1.x, V4.3.x / WSTG-ATHZ-04 / CS: GraphQL Cheat Sheet, API1 BOLA
requires: [backend, graphql]
---

# P98 — GraphQL BOLA (Broken Object Level Authorization)

## Overview
GraphQL Broken Object Level Authorization (BOLA) occurs when a resolver or field exposes an object by a client-supplied identifier (id, slug, relation) without verifying that the caller is allowed to read or mutate **that specific object**. GraphQL magnifies the classic IDOR problem: a single endpoint accepts arbitrarily nested queries, the schema itself advertises every type and relation (via introspection), and the framework will happily fetch related objects by id unless each resolver enforces ownership. The root cause is almost always *authentication without authorization* — the server confirms *who* the user is, then trusts the id argument to scope the result. Object-level checks pushed "up" into a single middleware or applied only at the root query rarely survive nested resolvers and mutations.

## What to check
- Does any resolver (`Query.*`, `Mutation.*`, type field) accept an `id`/identifier argument and return an object without checking `object.ownerId === ctx.user.id` (or the equivalent role/tenant check)?
- Are authorization checks applied **per resolver / per field**, or only once at the root query / via a global auth middleware that proves the request is authenticated but not that it owns the object?
- Do **nested** resolvers (e.g. `User.posts`, `Post.comments`, `Order.customer`) inherit the parent's authorization, or can they re-load an object by id and bypass the parent's scoping? `dataloader` batches keyed by raw id are a frequent leak point.
- Are mutations (`updateUser`, `deletePost`, `cancelOrder`) checked for ownership on the *target* object, not just that the caller is logged in?
- Does a list/connection resolver leak cross-tenant rows when given a foreign id in a filter, cursor, or `after` argument?
- Are field-level directives (`@auth`, `@hasRole`, `@canAccess`) consistently applied across **every** field, or are some resolvers left bare?
- Is introspection enabled in production, exposing the full schema (every object + relation) to an attacker mapping the attack surface?
- Are persisted queries / allow-lists used, or can the client submit arbitrary queries (deeply nested batched BOLA)?

## Static signals
Resolver returns object by id without ownership check:
- TS/JS (Apollo, GraphQL.js, Mercurius, Yoga): `user: (_, { id }) => User.findById(id)`, `user: (parent, { id }) => prisma.user.findUnique({ where: { id } })`
- Python (Strawberry, Graphene, Ariadne, PynamoDB): `def resolve_user(root, info, id): return User.objects.get(pk=id)`, `Query.user = graphene.Field(UserType, id=graphene.ID(required=True)); def resolve_user(root, info, id): return UserType.objects.get(pk=id)`
- Java (GraphQL Java/Kickstart, Spring for GraphQL): `@QueryMapping User user(@Argument Long id){ return userRepo.findById(id); }`, `@SchemaMapping public Customer customer(Order order){ return customerRepo.findById(order.getCustomerId()); }`
- Go (gqlgen): `func (r *queryResolver) User(ctx context.Context, id string) (*User, error){ return r.repo.UserByID(id) }` — no `ctx` auth check
- Ruby (graphql-ruby): `field :user, UserType, null: true do argument :id, ID end; def user(id:); User.find(id); end`
- PHP (Lighthouse / API Platform / webonyx): `user($root, array $args): User { return User::find($args['id']); }`

Auth only at root / global middleware, none inside resolver:
- Apollo `context: ({ req }) => ({ user: req.user })` with no per-resolver guard
- Express middleware `app.use('/graphql', authMiddleware)` only — resolvers read `ctx.user` but never compare it
- Decorator/presenter pattern missing: no `@auth`, `@login_required`, `@authorize` on the resolver

Nested resolver re-fetches by raw id (parent scoping bypassed):
- `Post: { author: (post) => User.findById(post.authorId) }` returning a private profile the child shouldn't see
- DataLoader `.load(id)` keyed by attacker-supplied id: `userLoader.load(args.id)`

Mutations without target ownership:
- `updatePost: (_, { id, input }) => Post.findByIdAndUpdate(id, input)`
- `@MutationMapping void deleteOrder(@Argument Long id){ repo.deleteById(id); }`

Field directives missing or inconsistent:
- Schema fields with no `@auth`/`@requireAuth`; only some queries guarded
- `buildSubgraph` / `makeExecutableSchema` with directive **definitions** but no directive **resolvers** wired up

## False positives
- Every resolver and field is consistently guarded by a schema directive (`@auth`, `@hasRole(role: "ADMIN")`) backed by a **working** directive resolver/middleware, or by a code-level guard (`requireAuth`, `@login_required`) that performs object-level checks.
- The id is a capability / unguessable signed token (e.g. `Order.ref` is a random 128-bit value used as a capability) AND server-side ownership is still validated — token alone is not enough, treat as defense-in-depth only.
- Persisted-query allow-listing is enforced server-side (APQ disabled, query-hash allow-list), the operation is fixed, and the resolver still authorizes — this narrows but does **not** remove the need for object-level checks.
- The object is intentionally public (e.g. `Query.publicProfile`, `Query.publishedPosts`) and contains no private fields — verify no private field leaks through a nested resolver.
- A centralized authorization layer (e.g. PostgREST RLS, ORM row-level security, OPA policy on every resolver) demonstrably scopes **every** type, not just top-level queries.

## Attack scenario
1. Attacker registers a normal account and notes their own `userId` is an integer (`1024`).
2. Via introspection (`{ __type(name:"Query"){ fields{ name args{ name } } } }`) they discover `Query.user(id: ID!): User` and `Mutation.updateUser(id: ID!, input: UserInput!): User`.
3. They query `query { user(id: 1) { email ssn orders { id total } } }` — the resolver runs `User.findById(1)` and returns another user's PII plus their orders, because no ownership check exists inside the resolver.
4. The attacker enumerates ids 1..N (trivial sequential walking), dumping every account's profile, email, and order history in a single batched query.
5. Using `Mutation.updateUser(id: 1, input: { email: "attacker@evil" })` they trigger password reset on the victim's account, achieving full account takeover.

## Impact
- **Confidentiality**: mass disclosure of other users' PII, financial records, medical data, internal documents — often the entire dataset via sequential/batched id walking in one request.
- **Integrity**: unauthorized mutation (update/delete/create) on objects the attacker does not own — account takeover, fraudulent transactions, data destruction.
- **Availability**: mass deletion or corruption of records via unauthorized mutations.
- Severity is routinely **Critical**: GraphQL batching + nested resolvers let one authenticated (or even anonymous) request enumerate and exfiltrate the whole tenant's data, and the schema introspection hands the attacker the full map.

## Remediation
Authorize on the **object** in every resolver — never rely on authentication alone:
```ts
// VULNERABLE — authenticated but not authorized; any caller can read any user
const resolvers = {
  Query: {
    user: (_, { id }) => User.findById(id),
  },
  Mutation: {
    updateUser: (_, { id, input }) => User.findByIdAndUpdate(id, input, { new: true }),
  },
};

// SAFE — object-level ownership check on every resolver/field
const resolvers = {
  Query: {
    user: requireAuth((_, { id }, ctx) =>
      User.findOne({ _id: id, ownerId: ctx.user.id }) // null if not owned
    ),
  },
  Mutation: {
    updateUser: requireAuth(async (_, { id, input }, ctx) => {
      const owner = await User.findById(id).select('ownerId');
      if (!owner || owner.ownerId !== ctx.user.id) throw new ForbiddenError();
      return User.findByIdAndUpdate(id, input, { new: true });
    }),
  },
};
```
Use schema directives (`@auth`, `@hasRole`) or a per-resolver guard consistently across **every** field including nested types and mutations; verify the directive resolver is actually wired up. Disable introspection and depth/complexity in production, enforce persisted-query allow-lists, and apply ORM row-level security as defense-in-depth — but none of these substitute for explicit object-level authorization in the resolver.

## References
- OWASP ASVS V4.1.x (object-level authorization), V4.3.x (operation-level authorization)
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References
- OWASP Cheat Sheet: GraphQL Cheat Sheet (authorization section), Injection Prevention / Authorization Cheat Sheet
