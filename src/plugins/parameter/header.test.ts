import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { HeaderParserPlugin } from "./header.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { AuditParameter, type HttpRequest, BuiltinMutationType } from "../../types/models.ts";
import { HeaderParameter } from "./header.ts";

const noopLogger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function flatTargets(results: AuditParameter[][]): AuditParameter[] {
  return results.flat();
}

describe("HeaderParserPlugin", () => {
  it("parses request headers", async () => {
    const plugin = new HeaderParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
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
        new HeaderParameter({ name: "content-type" }, "application/json", [
          BuiltinMutationType.ReplaceValue,
          BuiltinMutationType.AppendValue,
          BuiltinMutationType.PrependValue,
        ]),
        new HeaderParameter({ name: "x-custom" }, "value", [
          BuiltinMutationType.ReplaceValue,
          BuiltinMutationType.AppendValue,
          BuiltinMutationType.PrependValue,
        ]),
      ]),
    );
  });

  it("returns empty array when no headers are present", async () => {
    const plugin = new HeaderParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
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
