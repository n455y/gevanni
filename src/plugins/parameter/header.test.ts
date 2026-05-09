import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { HeaderParserPlugin } from "./header.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { InspectionParameter, type HttpRequest } from "../../types/models.js";
import { HeaderParameter } from "./header.js";
import { ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function flatParams(results: InspectionParameter[][]): InspectionParameter[] {
  return results.flat();
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
        new HeaderParameter(
          { name: "content-type" },
          "application/json",
          [ReplaceValue, AppendValue, PrependValue],
        ),
        new HeaderParameter(
          { name: "x-custom" },
          "value",
          [ReplaceValue, AppendValue, PrependValue],
        ),
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
