import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { GraphQLParserPlugin } from "./graphql.js";
import {
  GraphQLQueryParameter,
  GraphQLVariableParameter,
} from "../../types/models.js";
import type { InspectionParameter } from "../../types/models.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import type { HttpRequest } from "../../types/models.js";

type AnyGraphQLParam = GraphQLQueryParameter | GraphQLVariableParameter;

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

function flatParams(results: InspectionParameter<unknown, unknown>[][]): AnyGraphQLParam[] {
  return results.flat() as AnyGraphQLParam[];
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
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    // query + variables.id
    expect(params).toHaveLength(2);

    const queryParam = params.find(
      (p): p is GraphQLQueryParameter =>
        p instanceof GraphQLQueryParameter &&
        p.location.field === "query",
    );
    expect(queryParam).toBeDefined();
    expect(queryParam!.originalValue).toBe(
      "query GetUser($id: ID!){ user(id: $id){ name } }",
    );

    const varParam = params.find(
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
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    // query + variables.input.name + variables.input.age
    expect(params).toHaveLength(3);

    const nameParam = params.find(
      (p): p is GraphQLVariableParameter =>
        p instanceof GraphQLVariableParameter &&
        p.location.path.join(".") === "variables.input.name",
    );
    expect(nameParam).toBeDefined();
    expect(nameParam!.originalValue).toBe("test");

    const ageParam = params.find(
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
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    // query + operationName
    expect(params).toHaveLength(2);

    const opParam = params.find(
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
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(0);
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
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(0);
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
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(0);
  });

  it("returns empty for invalid JSON", async () => {
    const plugin = new GraphQLParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(`{invalid json}`);
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(0);
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
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    // query + variables.ids.0 + variables.ids.1
    expect(params).toHaveLength(3);

    const id0 = params.find(
      (p): p is GraphQLVariableParameter =>
        p instanceof GraphQLVariableParameter &&
        p.location.path.join(".") === "variables.ids.0",
    );
    expect(id0).toBeDefined();
    expect(id0!.originalValue).toBe("1");

    const id1 = params.find(
      (p): p is GraphQLVariableParameter =>
        p instanceof GraphQLVariableParameter &&
        p.location.path.join(".") === "variables.ids.1",
    );
    expect(id1).toBeDefined();
    expect(id1!.originalValue).toBe("2");
  });
});
