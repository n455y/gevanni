import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { JsonParserPlugin } from "./json.js";
import {
  JsonPrimitiveParameter,
  JsonArrayParameter,
  JsonObjectParameter,
} from "../../types/models.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import type {
  HttpRequest,
  InspectionParameter,
} from "../../types/models.js";

type AnyJsonParam =
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

function flatParams(results: InspectionParameter<unknown, unknown>[][]): AnyJsonParam[] {
  return results.flat() as AnyJsonParam[];
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
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    // Should contain:
    // - root object: { path: [] }
    // - user object: { path: ["user"] }
    // - user.name primitive: { path: ["user", "name"] }
    // - user.age primitive: { path: ["user", "age"] }
    expect(params).toHaveLength(4);

    const rootObj = params.find(
      (p): p is JsonObjectParameter =>
        p instanceof JsonObjectParameter &&
        p.location.path.length === 0,
    );
    expect(rootObj).toBeDefined();

    const userObj = params.find(
      (p): p is JsonObjectParameter =>
        p instanceof JsonObjectParameter &&
        p.location.path.includes("user") &&
        p.location.path.length === 1,
    );
    expect(userObj).toBeDefined();

    const nameParam = params.find(
      (p): p is JsonPrimitiveParameter =>
        p instanceof JsonPrimitiveParameter &&
        p.location.path.length === 2 &&
        p.location.path[0] === "user" &&
        p.location.path[1] === "name",
    );
    expect(nameParam).toBeDefined();
    expect(nameParam!.originalValue).toBe("test");

    const ageParam = params.find(
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

    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(0);
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

    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(0);
  });

  it("returns empty array for invalid JSON", async () => {
    const plugin = new JsonParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{invalid json}`);
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(0);
  });

  it("parses JSON arrays with indexed paths", async () => {
    const plugin = new JsonParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"items":["a","b"]}`);
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    // root object + items array + items[0] + items[1]
    expect(params).toHaveLength(4);

    const arrayParam = params.find(
      (p): p is JsonArrayParameter =>
        p instanceof JsonArrayParameter &&
        p.location.path.length === 1 &&
        p.location.path[0] === "items",
    );
    expect(arrayParam).toBeDefined();
    expect(arrayParam!.originalValue).toEqual(["a", "b"]);

    const item0 = params.find(
      (p): p is JsonPrimitiveParameter =>
        p instanceof JsonPrimitiveParameter &&
        p.location.path.length === 2 &&
        p.location.path[0] === "items" &&
        p.location.path[1] === "0",
    );
    expect(item0).toBeDefined();
    expect(item0!.originalValue).toBe("a");

    const item1 = params.find(
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
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    // root object + active + deleted = 3
    expect(params).toHaveLength(3);

    const activeParam = params.find(
      (p): p is JsonPrimitiveParameter =>
        p instanceof JsonPrimitiveParameter &&
        p.location.path[0] === "active",
    );
    expect(activeParam!.originalValue).toBe(true);

    const deletedParam = params.find(
      (p): p is JsonPrimitiveParameter =>
        p instanceof JsonPrimitiveParameter &&
        p.location.path[0] === "deleted",
    );
    expect(deletedParam!.originalValue).toBeNull();
  });
});
