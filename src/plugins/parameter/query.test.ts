import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { QueryParserPlugin, QueryMutationPlugin } from "./query.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { ApplyMutationCommand } from "../../commands/mutation.ts";
import { AuditParameter, type HttpRequest } from "../../types/models.ts";
import { QueryParameter } from "./query.ts";
import { JsonPrimitiveParameter } from "./json.ts";
import { QueryMutation } from "./query.ts";
import { Payload as toPayload } from "../../types/branded.ts";
import {
  MutationType,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.ts";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function flatParams(results: AuditParameter[][]): AuditParameter[] {
  return results.flat();
}

function makeQueryInstruction(
  paramName: string,
  originalValue: string,
  payload: string,
  method: MutationType,
): QueryMutation {
  return new QueryMutation(
    new QueryParameter({ name: paramName }, originalValue, [
      ReplaceValue,
      AppendValue,
      PrependValue,
    ]),
    toPayload(payload),
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

    const targets = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(2);
    expect(targets).toEqual(
      expect.arrayContaining([
        new QueryParameter({ name: "foo" }, "bar", [
          ReplaceValue,
          AppendValue,
          PrependValue,
        ]),
        new QueryParameter({ name: "baz" }, "123", [
          ReplaceValue,
          AppendValue,
          PrependValue,
        ]),
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

    const targets = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
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

    const targets = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
  });
});

describe("QueryMutationPlugin", () => {
  it("replaces query parameter value with payload", async () => {
    const plugin = new QueryMutationPlugin();
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
      new ApplyMutationCommand(request, [instruction]),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("INJECTED");
    expect(result.method).toBe("GET");
    expect(result.headers).toEqual({});
    expect(result.body).toBeNull();
  });

  it("appends payload to existing query parameter value", async () => {
    const plugin = new QueryMutationPlugin();
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
      new ApplyMutationCommand(request, [instruction]),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("barINJECTED");
  });

  it("prepends payload to existing query parameter value", async () => {
    const plugin = new QueryMutationPlugin();
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
      new ApplyMutationCommand(request, [instruction]),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("INJECTEDbar");
  });

  it("returns request unchanged when no query mutations", async () => {
    const plugin = new QueryMutationPlugin();
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

    const instruction = new JsonPrimitiveParameter(
      { path: ["user", "name"] },
      "test",
      [ReplaceValue, AppendValue, PrependValue],
    ).createMutation(toPayload("INJECTED"), ReplaceValue);

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("handles multiple query parameters", async () => {
    const plugin = new QueryMutationPlugin();
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

    const mutations = [
      makeQueryInstruction("foo", "bar", "X", ReplaceValue),
      makeQueryInstruction("baz", "123", "Y", AppendValue),
    ];

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, mutations),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("X");
    expect(resultUrl.searchParams.get("baz")).toBe("123Y");
  });
});
