import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { QueryParserPlugin } from "./query-parser.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import type { HttpRequest, QueryParameter } from "../../types/models.js";
import type { Brand, TamperMethod } from "../../types/branded.js";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function flatParams(results: QueryParameter[][]): QueryParameter[] {
  return results.flat() as QueryParameter[];
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
        {
          type: "query" as Brand<"query", "ParameterType">,
          location: { name: "foo" },
          originalValue: "bar",
          allowedTampers: [
            "replaceValue" as TamperMethod,
            "appendValue" as TamperMethod,
            "prependValue" as TamperMethod,
          ],
        },
        {
          type: "query" as Brand<"query", "ParameterType">,
          location: { name: "baz" },
          originalValue: "123",
          allowedTampers: [
            "replaceValue" as TamperMethod,
            "appendValue" as TamperMethod,
            "prependValue" as TamperMethod,
          ],
        },
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
