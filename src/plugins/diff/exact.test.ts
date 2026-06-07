import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { ExactDiffPlugin } from "./exact.ts";
import { DiffCommand } from "../../commands/diff.ts";
import { ExchangeId } from "../../types/branded.ts";

let commandBus: InMemoryCommandBus;
const noopLogger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeExchange(statusCode: number, body: string) {
  return {
    id: ExchangeId("test-exchange-id"),
    request: { method: "GET", url: "http://test.com", headers: {}, body: null },
    response: { statusCode, headers: {}, body: Buffer.from(body) },
  };
}

describe("ExactDiffPlugin", () => {
  it("detects vulnerability when response bodies differ", async () => {
    const plugin = new ExactDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeExchange(200, '{"id":1}') },
        { label: "false", exchange: makeExchange(200, '{"id":0}') },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(true);
    expect(result.evidenceExchanges).toHaveLength(2);
  });

  it("detects diff when status codes differ", async () => {
    const plugin = new ExactDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeExchange(200, "same") },
        { label: "false", exchange: makeExchange(500, "same") },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(true);
  });

  it("returns not vulnerable when responses are identical", async () => {
    const plugin = new ExactDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeExchange(200, "same") },
        { label: "false", exchange: makeExchange(200, "same") },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(false);
    expect(result.evidenceExchanges).toHaveLength(0);
  });

  it("returns not vulnerable when pairs are incomplete", async () => {
    const plugin = new ExactDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(new DiffCommand([]));

    expect(result.handled).toBe(false);
  });

  it("chains to next plugin when first skips", async () => {
    const skipPlugin = new ExactDiffPlugin();
    await skipPlugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(new DiffCommand([]));

    expect(result.handled).toBe(false);
  });

  it("stops at first plugin that handles", async () => {
    const plugin = new ExactDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeExchange(200, "a") },
        { label: "false", exchange: makeExchange(200, "b") },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(true);
  });
});
