import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { JsonDiffPlugin } from "./json.ts";
import { DiffCommand } from "../../commands/diff.ts";
import { ExchangeId } from "../../types/branded.ts";

let commandBus: InMemoryCommandBus;
const noopLogger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeJsonExchange(statusCode: number, body: string) {
  return {
    id: ExchangeId("test-exchange-id"),
    request: { method: "GET", url: "http://test.com", headers: {}, body: null },
    response: { statusCode, headers: { "content-type": "application/json" }, body: Buffer.from(body) },
  };
}

function makeExchange(statusCode: number, body: string) {
  return {
    id: ExchangeId("test-exchange-id"),
    request: { method: "GET", url: "http://test.com", headers: {}, body: null },
    response: { statusCode, headers: {}, body: Buffer.from(body) },
  };
}

describe("JsonDiffPlugin", () => {
  it("detects diff when value changes but structure is same", async () => {
    const plugin = new JsonDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeJsonExchange(200, '{"id":1,"name":"Alice"}') },
        { label: "false", exchange: makeJsonExchange(200, '{"id":2,"name":"Bob"}') },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(false);
  });

  it("detects diff when structure differs", async () => {
    const plugin = new JsonDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeJsonExchange(200, '{"id":1,"name":"Alice"}') },
        { label: "false", exchange: makeJsonExchange(200, '{"id":1}') },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(true);
  });

  it("detects diff when array length differs", async () => {
    const plugin = new JsonDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeJsonExchange(200, '{"items":[{"id":1},{"id":2}]}') },
        { label: "false", exchange: makeJsonExchange(200, '{"items":[{"id":1}]}') },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(true);
  });

  it("skips non-JSON content type", async () => {
    const plugin = new JsonDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeExchange(200, "hello") },
        { label: "false", exchange: makeExchange(200, "world") },
      ]),
    );

    expect(result.handled).toBe(false);
  });

  it("detects diff when status codes differ", async () => {
    const plugin = new JsonDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeJsonExchange(200, '{"id":1}') },
        { label: "false", exchange: makeJsonExchange(500, '{"id":1}') },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(true);
  });

  it("handles same structure with nested objects", async () => {
    const plugin = new JsonDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeJsonExchange(200, '{"user":{"id":1,"name":"Alice"},"ts":123}') },
        { label: "false", exchange: makeJsonExchange(200, '{"user":{"id":2,"name":"Bob"},"ts":456}') },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(false);
  });
});
