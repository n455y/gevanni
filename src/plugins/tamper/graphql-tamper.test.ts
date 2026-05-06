import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { GraphQLTamperPlugin } from "./graphql-tamper.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import type { HttpRequest, TamperInstruction } from "../../types/models.js";
import type { Brand } from "../../types/branded.js";
import { TamperMethod, ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";
import { QueryParameterType } from "../parser/query-parser.js";
import {
  GraphQLQueryParameterType,
  GraphQLVariableParameterType,
} from "../parser/graphql-parser.js";

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

function makeQueryInstruction(
  field: string,
  payload: string,
  method: typeof TamperMethod,
): TamperInstruction {
  return {
    parameter: {
      type: GraphQLQueryParameterType,
      location: { field },
      originalValue: "",
      allowedTampers: [ReplaceValue, AppendValue, PrependValue],
    },
    payload: payload as Brand<string, "Payload">,
    method,
  };
}

function makeVariableInstruction(
  path: string[],
  originalValue: unknown,
  payload: string,
  method: typeof TamperMethod,
): TamperInstruction {
  return {
    parameter: {
      type: GraphQLVariableParameterType,
      location: { path },
      originalValue,
      allowedTampers: [ReplaceValue, AppendValue, PrependValue],
    },
    payload: payload as Brand<string, "Payload">,
    method,
  };
}

describe("GraphQLTamperPlugin", () => {
  it("replaces query string", async () => {
    const plugin = new GraphQLTamperPlugin();
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
      new ApplyTamperCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.query).toBe("INJECTED");
    expect(result.url).toBe("http://example.com/graphql");
    expect(result.headers).toEqual({ "content-type": "application/json" });
  });

  it("appends payload to query string", async () => {
    const plugin = new GraphQLTamperPlugin();
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
      new ApplyTamperCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.query).toBe("{ users { name } }INJECTED");
  });

  it("prepends payload to query string", async () => {
    const plugin = new GraphQLTamperPlugin();
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
      new ApplyTamperCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.query).toBe("INJECTED{ users { name } }");
  });

  it("replaces variable value", async () => {
    const plugin = new GraphQLTamperPlugin();
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
      new ApplyTamperCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.variables.id).toBe("INJECTED");
  });

  it("appends payload to variable value", async () => {
    const plugin = new GraphQLTamperPlugin();
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
      new ApplyTamperCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.variables.id).toBe("123INJECTED");
  });

  it("handles nested variable tampering", async () => {
    const plugin = new GraphQLTamperPlugin();
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
      new ApplyTamperCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.variables.input.name).toBe("INJECTED");
    expect(parsed.variables.input.email).toBe("a@b.com");
  });

  it("returns request unchanged when no GraphQL instructions", async () => {
    const plugin = new GraphQLTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"{ users { name } }","variables":{}}`,
    );
    const instruction: TamperInstruction = {
      parameter: {
        type: QueryParameterType,
        location: { name: "foo" },
        originalValue: "bar",
        allowedTampers: [ReplaceValue, AppendValue, PrependValue],
      },
      payload: "INJECTED" as Brand<string, "Payload">,
      method: ReplaceValue,
    };

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("returns request unchanged when body is null", async () => {
    const plugin = new GraphQLTamperPlugin();
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
      new ApplyTamperCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("handles multiple GraphQL instructions", async () => {
    const plugin = new GraphQLTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeGraphQLRequest(
      `{"query":"{ users { name } }","variables":{"id":"123","name":"test"}}`,
    );
    const instructions = [
      makeVariableInstruction(
        ["variables", "id"],
        "123",
        "X",
        ReplaceValue,
      ),
      makeVariableInstruction(
        ["variables", "name"],
        "test",
        "Y",
        AppendValue,
      ),
    ];

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, instructions),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.variables.id).toBe("X");
    expect(parsed.variables.name).toBe("testY");
  });
});
