import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { GraphQLParserPlugin, GraphQLMutationPlugin } from "./graphql.ts";
import {
  GraphQLQueryParameter,
  GraphQLVariableParameter,
  GraphQLQueryMutation,
  GraphQLVariableMutation,
} from "./graphql.ts";
import { QueryParameter } from "./query.ts";
import type {
  AuditTarget,
  HttpRequest,
  JsonValue,
} from "../../types/models.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { ApplyMutationCommand } from "../../commands/mutation.ts";
import type { Brand } from "../../types/branded.ts";
import {
  MutationType,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.ts";

type AnyGraphQLTarget = GraphQLQueryParameter | GraphQLVariableParameter;

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeGraphQLRequest(body: string): HttpRequest {
  return {
    method: "POST",
    url: "http://example.com/graphql",
    headers: { "content-type": "application/json" },
    body: Buffer.from(body, "utf-8"),
  };
}

function flatTargets(results: AuditTarget[][]): AnyGraphQLTarget[] {
  return results.flat() as AnyGraphQLTarget[];
}

function makeQueryInstruction(
  field: string,
  payload: string,
  method: MutationType,
): GraphQLQueryMutation {
  return new GraphQLQueryMutation(
    new GraphQLQueryParameter({ field }, "", [
      ReplaceValue,
      AppendValue,
      PrependValue,
    ]),
    payload as Brand<string, "Payload">,
    method,
  );
}

function makeVariableInstruction(
  path: string[],
  originalValue: JsonValue,
  payload: string,
  method: MutationType,
): GraphQLVariableMutation {
  return new GraphQLVariableMutation(
    new GraphQLVariableParameter({ path }, originalValue, [
      ReplaceValue,
      AppendValue,
      PrependValue,
    ]),
    payload as Brand<string, "Payload">,
    method,
  );
}

describe("GraphQLParserPlugin", () => {
  it("parses GraphQL request with query and variables", async () => {
    const plugin = new GraphQLParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"query GetUser($id: ID!){ user(id: $id){ name } }","variables":{"id":"123"}}`,
    );
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(2);

    const queryParam = targets.find(
      (p): p is GraphQLQueryParameter =>
        p instanceof GraphQLQueryParameter && p.location.field === "query",
    );
    expect(queryParam).toBeDefined();
    expect(queryParam!.originalValue).toBe(
      "query GetUser($id: ID!){ user(id: $id){ name } }",
    );

    const varParam = targets.find(
      (p): p is GraphQLVariableParameter =>
        p instanceof GraphQLVariableParameter &&
        p.location.path.length === 2 &&
        p.location.path[0] === "variables" &&
        p.location.path[1] === "id",
    );
    expect(varParam).toBeDefined();
    expect(varParam!.originalValue).toBe("123");
  });

  it("parses GraphQL request with nested variables", async () => {
    const plugin = new GraphQLParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"mutation{ createUser(input: $input) { id } }","variables":{"input":{"name":"test","age":25}}}`,
    );
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(3);

    const nameParam = targets.find(
      (p): p is GraphQLVariableParameter =>
        p instanceof GraphQLVariableParameter &&
        p.location.path.join(".") === "variables.input.name",
    );
    expect(nameParam).toBeDefined();
    expect(nameParam!.originalValue).toBe("test");

    const ageParam = targets.find(
      (p): p is GraphQLVariableParameter =>
        p instanceof GraphQLVariableParameter &&
        p.location.path.join(".") === "variables.input.age",
    );
    expect(ageParam).toBeDefined();
    expect(ageParam!.originalValue).toBe(25);
  });

  it("parses GraphQL request with operationName", async () => {
    const plugin = new GraphQLParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"query A{ a } query B{ b }","operationName":"B"}`,
    );
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(2);

    const opParam = targets.find(
      (p): p is GraphQLQueryParameter =>
        p instanceof GraphQLQueryParameter &&
        p.location.field === "operationName",
    );
    expect(opParam).toBeDefined();
    expect(opParam!.originalValue).toBe("B");
  });

  it("returns empty for non-GraphQL JSON", async () => {
    const plugin = new GraphQLParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(`{"name":"test","age":25}`);
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
  });

  it("returns empty when content-type is not application/json", async () => {
    const plugin = new GraphQLParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/graphql",
      headers: { "content-type": "text/plain" },
      body: Buffer.from(`{"query":"{ users { name } }"}`, "utf-8"),
    };
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
  });

  it("returns empty when body is null", async () => {
    const plugin = new GraphQLParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/graphql",
      headers: { "content-type": "application/json" },
      body: null,
    };
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
  });

  it("returns empty for invalid JSON", async () => {
    const plugin = new GraphQLParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(`{invalid json}`);
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
  });

  it("parses GraphQL request with array variables", async () => {
    const plugin = new GraphQLParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"query($ids: [ID!]!){ users(ids: $ids){ name } }","variables":{"ids":["1","2"]}}`,
    );
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(3);

    const id0 = targets.find(
      (p): p is GraphQLVariableParameter =>
        p instanceof GraphQLVariableParameter &&
        p.location.path.join(".") === "variables.ids.0",
    );
    expect(id0).toBeDefined();
    expect(id0!.originalValue).toBe("1");

    const id1 = targets.find(
      (p): p is GraphQLVariableParameter =>
        p instanceof GraphQLVariableParameter &&
        p.location.path.join(".") === "variables.ids.1",
    );
    expect(id1).toBeDefined();
    expect(id1!.originalValue).toBe("2");
  });
});

describe("GraphQLMutationPlugin", () => {
  it("replaces query string", async () => {
    const plugin = new GraphQLMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"{ users { name } }","variables":{}}`,
    );
    const instruction = makeQueryInstruction("query", "INJECTED", ReplaceValue);

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.query).toBe("INJECTED");
    expect(result.url).toBe("http://example.com/graphql");
    expect(result.headers).toEqual({ "content-type": "application/json" });
  });

  it("appends payload to query string", async () => {
    const plugin = new GraphQLMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"{ users { name } }","variables":{}}`,
    );
    const instruction = makeQueryInstruction("query", "INJECTED", AppendValue);

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.query).toBe("{ users { name } }INJECTED");
  });

  it("prepends payload to query string", async () => {
    const plugin = new GraphQLMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"{ users { name } }","variables":{}}`,
    );
    const instruction = makeQueryInstruction("query", "INJECTED", PrependValue);

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.query).toBe("INJECTED{ users { name } }");
  });

  it("replaces variable value", async () => {
    const plugin = new GraphQLMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"query($id:ID!){ user(id:$id){ name } }","variables":{"id":"123"}}`,
    );
    const instruction = makeVariableInstruction(
      ["variables", "id"],
      "123",
      "INJECTED",
      ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.variables.id).toBe("INJECTED");
  });

  it("appends payload to variable value", async () => {
    const plugin = new GraphQLMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"query($id:ID!){ user(id:$id){ name } }","variables":{"id":"123"}}`,
    );
    const instruction = makeVariableInstruction(
      ["variables", "id"],
      "123",
      "INJECTED",
      AppendValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.variables.id).toBe("123INJECTED");
  });

  it("handles nested variable tampering", async () => {
    const plugin = new GraphQLMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"mutation($input:UserInput!){ createUser(input:$input){ id } }","variables":{"input":{"name":"test","email":"a@b.com"}}}`,
    );
    const instruction = makeVariableInstruction(
      ["variables", "input", "name"],
      "test",
      "INJECTED",
      ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.variables.input.name).toBe("INJECTED");
    expect(parsed.variables.input.email).toBe("a@b.com");
  });

  it("returns request unchanged when no GraphQL mutations", async () => {
    const plugin = new GraphQLMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"{ users { name } }","variables":{}}`,
    );
    const instruction = new QueryParameter({ name: "foo" }, "bar", [
      ReplaceValue,
      AppendValue,
      PrependValue,
    ]).createMutation("INJECTED" as Brand<string, "Payload">, ReplaceValue);

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("returns request unchanged when body is null", async () => {
    const plugin = new GraphQLMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/graphql",
      headers: { "content-type": "application/json" },
      body: null,
    };

    const instruction = makeQueryInstruction("query", "INJECTED", ReplaceValue);

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("handles multiple GraphQL mutations", async () => {
    const plugin = new GraphQLMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"{ users { name } }","variables":{"id":"123","name":"test"}}`,
    );
    const mutations = [
      makeVariableInstruction(["variables", "id"], "123", "X", ReplaceValue),
      makeVariableInstruction(["variables", "name"], "test", "Y", AppendValue),
    ];

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, mutations),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.variables.id).toBe("X");
    expect(parsed.variables.name).toBe("testY");
  });
});
