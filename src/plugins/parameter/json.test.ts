import { beforeEach, describe, expect, it } from "vitest";
import { ApplyMutationCommand } from "../../commands/mutation.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import type { MutationType } from "../../types/branded.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/branded.ts";
import type { AuditParameter, HttpRequest } from "../../types/models.ts";
import {
  JsonArrayMutation,
  JsonArrayParameter,
  JsonMutationPlugin,
  JsonObjectParameter,
  JsonParserPlugin,
  JsonPrimitiveMutation,
  JsonPrimitiveParameter,
} from "./json.ts";
import { QueryParameter } from "./query.ts";

type AnyJsonTarget =
  | JsonPrimitiveParameter
  | JsonArrayParameter
  | JsonObjectParameter;

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeJsonRequest(body: string): HttpRequest {
  return {
    method: "POST",
    url: "http://example.com/api",
    headers: { "content-type": "application/json" },
    body: Buffer.from(body, "utf-8"),
  };
}

function flatTargets(results: AuditParameter[][]): AnyJsonTarget[] {
  return results.flat() as AnyJsonTarget[];
}

function makeJsonPrimitiveInstruction(
  path: string[],
  originalValue: unknown,
  payload: string,
  method: MutationType,
): JsonPrimitiveMutation {
  return new JsonPrimitiveMutation(
    new JsonPrimitiveParameter(
      { path },
      originalValue as string | number | boolean | null,
      [
        BuiltinMutationType.ReplaceValue,
        BuiltinMutationType.AppendValue,
        BuiltinMutationType.PrependValue,
      ],
    ),
    BuiltinPayload.String(payload),
    method,
  );
}

describe("JsonParserPlugin", () => {
  it("parses nested JSON body and extracts parameters with paths", async () => {
    const plugin = new JsonParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"user":{"name":"test","age":25}}`);
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(4);

    const rootObj = targets.find(
      (p): p is JsonObjectParameter =>
        p instanceof JsonObjectParameter && p.location.path.length === 0,
    );
    expect(rootObj).toBeDefined();

    const userObj = targets.find(
      (p): p is JsonObjectParameter =>
        p instanceof JsonObjectParameter &&
        p.location.path.includes("user") &&
        p.location.path.length === 1,
    );
    expect(userObj).toBeDefined();

    const nameParam = targets.find(
      (p): p is JsonPrimitiveParameter =>
        p instanceof JsonPrimitiveParameter &&
        p.location.path.length === 2 &&
        p.location.path[0] === "user" &&
        p.location.path[1] === "name",
    );
    expect(nameParam).toBeDefined();
    expect(nameParam!.originalValue).toBe("test");

    const ageParam = targets.find(
      (p): p is JsonPrimitiveParameter =>
        p instanceof JsonPrimitiveParameter &&
        p.location.path.length === 2 &&
        p.location.path[0] === "user" &&
        p.location.path[1] === "age",
    );
    expect(ageParam).toBeDefined();
    expect(ageParam!.originalValue).toBe(25);
  });

  it("returns empty array when content-type is not application/json", async () => {
    const plugin = new JsonParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/api",
      headers: { "content-type": "text/plain" },
      body: Buffer.from(`{"key":"value"}`, "utf-8"),
    };

    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
  });

  it("returns empty array when body is null", async () => {
    const plugin = new JsonParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/api",
      headers: { "content-type": "application/json" },
      body: null,
    };

    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
  });

  it("returns empty array for invalid JSON", async () => {
    const plugin = new JsonParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{invalid json}`);
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
  });

  it("parses JSON arrays with indexed paths", async () => {
    const plugin = new JsonParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"items":["a","b"]}`);
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(4);

    const arrayParam = targets.find(
      (p): p is JsonArrayParameter =>
        p instanceof JsonArrayParameter &&
        p.location.path.length === 1 &&
        p.location.path[0] === "items",
    );
    expect(arrayParam).toBeDefined();
    expect(arrayParam!.originalValue).toEqual(["a", "b"]);

    const item0 = targets.find(
      (p): p is JsonPrimitiveParameter =>
        p instanceof JsonPrimitiveParameter &&
        p.location.path.length === 2 &&
        p.location.path[0] === "items" &&
        p.location.path[1] === "0",
    );
    expect(item0).toBeDefined();
    expect(item0!.originalValue).toBe("a");

    const item1 = targets.find(
      (p): p is JsonPrimitiveParameter =>
        p instanceof JsonPrimitiveParameter &&
        p.location.path.length === 2 &&
        p.location.path[0] === "items" &&
        p.location.path[1] === "1",
    );
    expect(item1).toBeDefined();
    expect(item1!.originalValue).toBe("b");
  });

  it("handles boolean and null primitives", async () => {
    const plugin = new JsonParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"active":true,"deleted":null}`);
    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(3);

    const activeParam = targets.find(
      (p): p is JsonPrimitiveParameter =>
        p instanceof JsonPrimitiveParameter && p.location.path[0] === "active",
    );
    expect(activeParam!.originalValue).toBe(true);

    const deletedParam = targets.find(
      (p): p is JsonPrimitiveParameter =>
        p instanceof JsonPrimitiveParameter && p.location.path[0] === "deleted",
    );
    expect(deletedParam!.originalValue).toBeNull();
  });
});

describe("JsonMutationPlugin", () => {
  it("replaces nested JSON primitive value", async () => {
    const plugin = new JsonMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"user":{"name":"test"}}`);
    const instruction = makeJsonPrimitiveInstruction(
      ["user", "name"],
      "test",
      "INJECTED",
      BuiltinMutationType.ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.user.name).toBe("INJECTED");
    expect(result.url).toBe("http://example.com/api");
    expect(result.headers).toEqual({ "content-type": "application/json" });
  });

  it("appends payload to JSON primitive value", async () => {
    const plugin = new JsonMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"user":{"name":"test"}}`);
    const instruction = makeJsonPrimitiveInstruction(
      ["user", "name"],
      "test",
      "INJECTED",
      BuiltinMutationType.AppendValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.user.name).toBe("testINJECTED");
  });

  it("prepends payload to JSON primitive value", async () => {
    const plugin = new JsonMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"user":{"name":"test"}}`);
    const instruction = makeJsonPrimitiveInstruction(
      ["user", "name"],
      "test",
      "INJECTED",
      BuiltinMutationType.PrependValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.user.name).toBe("INJECTEDtest");
  });

  it("returns request unchanged when no JSON mutations", async () => {
    const plugin = new JsonMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"user":{"name":"test"}}`);
    const instruction = new QueryParameter({ name: "foo" }, "bar", [
      BuiltinMutationType.ReplaceValue,
      BuiltinMutationType.AppendValue,
      BuiltinMutationType.PrependValue,
    ]).createMutation(
      BuiltinPayload.String("INJECTED"),
      BuiltinMutationType.ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("returns request unchanged when body is null", async () => {
    const plugin = new JsonMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/api",
      headers: { "content-type": "application/json" },
      body: null,
    };

    const instruction = makeJsonPrimitiveInstruction(
      ["name"],
      "test",
      "INJECTED",
      BuiltinMutationType.ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("handles multiple JSON mutations", async () => {
    const plugin = new JsonMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(
      `{"user":{"name":"test","email":"a@b.com"}}`,
    );
    const mutations = [
      makeJsonPrimitiveInstruction(
        ["user", "name"],
        "test",
        "X",
        BuiltinMutationType.ReplaceValue,
      ),
      makeJsonPrimitiveInstruction(
        ["user", "email"],
        "a@b.com",
        "Y",
        BuiltinMutationType.AppendValue,
      ),
    ];

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, mutations),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.user.name).toBe("X");
    expect(parsed.user.email).toBe("a@b.comY");
  });

  it("handles jsonArray type mutations", async () => {
    const plugin = new JsonMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"items":["a","b"]}`);

    const instruction = new JsonArrayMutation(
      new JsonArrayParameter(
        { path: ["items"] },
        ["a", "b"],
        [
          BuiltinMutationType.ReplaceValue,
          BuiltinMutationType.AppendValue,
          BuiltinMutationType.PrependValue,
        ],
      ),
      BuiltinPayload.String("INJECTED"),
      BuiltinMutationType.ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.items).toBe("INJECTED");
  });
});
