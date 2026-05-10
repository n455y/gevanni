import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { HeaderParserPlugin } from "./header.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { AuditTarget, type HttpRequest } from "../../types/models.ts";
import { HeaderParameter } from "./header.ts";
import { ReplaceValue, AppendValue, PrependValue } from "../../types/branded.ts";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function flatTargets(results: AuditTarget[][]): AuditTarget[] {
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

    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(2);
    expect(targets).toEqual(
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

    const targets = flatTargets(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
  });
});
