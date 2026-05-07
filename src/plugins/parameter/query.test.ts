import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { QueryParserPlugin, QueryTamperPlugin } from "./query.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import type { HttpRequest } from "../../types/models.js";
import { QueryParameter, JsonPrimitiveParameter, TamperInstruction, QueryTamperInstruction } from "../../types/models.js";
import type { Brand } from "../../types/branded.js";
import { TamperMethod, ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function flatParams(results: QueryParameter[][]): QueryParameter[] {
  return results.flat() as QueryParameter[];
}

function makeQueryInstruction(
  paramName: string,
  originalValue: string,
  payload: string,
  method: typeof TamperMethod,
): QueryTamperInstruction {
  return new QueryTamperInstruction(
    new QueryParameter(
      { name: paramName },
      originalValue,
      [ReplaceValue, AppendValue, PrependValue],
    ),
    payload as Brand<string, "Payload">,
    method,
  );
}

describe("QueryParserPlugin", () => {
  it("parses URL query string parameters", async () => {
    const plugin = new QueryParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?foo=bar&baz=123",
      headers: {},
      body: null,
    };

    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(2);
    expect(params).toEqual(
      expect.arrayContaining([
        new QueryParameter(
          { name: "foo" },
          "bar",
          [ReplaceValue, AppendValue, PrependValue],
        ),
        new QueryParameter(
          { name: "baz" },
          "123",
          [ReplaceValue, AppendValue, PrependValue],
        ),
      ]),
    );
  });

  it("returns empty array when URL has no query string", async () => {
    const plugin = new QueryParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com",
      headers: {},
      body: null,
    };

    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(0);
  });

  it("returns empty array for empty query string", async () => {
    const plugin = new QueryParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?",
      headers: {},
      body: null,
    };

    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(0);
  });
});

describe("QueryTamperPlugin", () => {
  it("replaces query parameter value with payload", async () => {
    const plugin = new QueryTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?foo=bar",
      headers: {},
      body: null,
    };

    const instruction = makeQueryInstruction(
      "foo",
      "bar",
      "INJECTED",
      ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("INJECTED");
    expect(result.method).toBe("GET");
    expect(result.headers).toEqual({});
    expect(result.body).toBeNull();
  });

  it("appends payload to existing query parameter value", async () => {
    const plugin = new QueryTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?foo=bar",
      headers: {},
      body: null,
    };

    const instruction = makeQueryInstruction(
      "foo",
      "bar",
      "INJECTED",
      AppendValue,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("barINJECTED");
  });

  it("prepends payload to existing query parameter value", async () => {
    const plugin = new QueryTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?foo=bar",
      headers: {},
      body: null,
    };

    const instruction = makeQueryInstruction(
      "foo",
      "bar",
      "INJECTED",
      PrependValue,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("INJECTEDbar");
  });

  it("returns request unchanged when no query instructions", async () => {
    const plugin = new QueryTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?foo=bar",
      headers: {},
      body: null,
    };

    const instruction = new TamperInstruction(
      new JsonPrimitiveParameter(
        { path: ["user", "name"] },
        "test",
        [ReplaceValue, AppendValue, PrependValue],
      ),
      "INJECTED" as Brand<string, "Payload">,
      ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("handles multiple query parameters", async () => {
    const plugin = new QueryTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?foo=bar&baz=123",
      headers: {},
      body: null,
    };

    const instructions = [
      makeQueryInstruction("foo", "bar", "X", ReplaceValue),
      makeQueryInstruction("baz", "123", "Y", AppendValue),
    ];

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, instructions),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("X");
    expect(resultUrl.searchParams.get("baz")).toBe("123Y");
  });
});
