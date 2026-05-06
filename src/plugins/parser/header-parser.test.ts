import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { HeaderParserPlugin, HeaderParameterType } from "./header-parser.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import type { HttpRequest } from "../../types/models.js";
import { ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";
import type { HeaderParameter } from "./header-parser.js";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function flatParams(results: HeaderParameter[][]): HeaderParameter[] {
  return results.flat() as HeaderParameter[];
}

describe("HeaderParserPlugin", () => {
  it("parses request headers", async () => {
    const plugin = new HeaderParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com",
      headers: {
        "content-type": "application/json",
        "x-custom": "value",
      },
      body: null,
    };

    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(2);
    expect(params).toEqual(
      expect.arrayContaining([
        {
          type: HeaderParameterType,
          location: { name: "content-type" },
          originalValue: "application/json",
          allowedTampers: [ReplaceValue, AppendValue, PrependValue],
        },
        {
          type: HeaderParameterType,
          location: { name: "x-custom" },
          originalValue: "value",
          allowedTampers: [ReplaceValue, AppendValue, PrependValue],
        },
      ]),
    );
  });

  it("returns empty array when no headers are present", async () => {
    const plugin = new HeaderParserPlugin();
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
});
