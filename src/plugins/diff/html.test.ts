import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { HtmlDiffPlugin } from "./html.ts";
import { DiffCommand } from "../../commands/diff.ts";
import { ExchangeId } from "../../types/branded.ts";

let commandBus: InMemoryCommandBus;
const noopLogger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeHtmlExchange(statusCode: number, body: string) {
  return {
    id: ExchangeId("test-exchange-id"),
    request: { method: "GET", url: "http://test.com", headers: {}, body: null },
    response: { statusCode, headers: { "content-type": "text/html" }, body: Buffer.from(body) },
  };
}

function makeExchange(statusCode: number, body: string) {
  return {
    id: ExchangeId("test-exchange-id"),
    request: { method: "GET", url: "http://test.com", headers: {}, body: null },
    response: { statusCode, headers: {}, body: Buffer.from(body) },
  };
}

describe("HtmlDiffPlugin", () => {
  it("ignores script tag differences", async () => {
    const plugin = new HtmlDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeHtmlExchange(200, '<div>Hello</div><script>var x=1;</script>') },
        { label: "false", exchange: makeHtmlExchange(200, '<div>Hello</div><script>var x=2;</script>') },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(false);
  });

  it("ignores style tag differences", async () => {
    const plugin = new HtmlDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeHtmlExchange(200, '<div>Hello</div><style>.a{color:red;}</style>') },
        { label: "false", exchange: makeHtmlExchange(200, '<div>Hello</div><style>.a{color:blue;}</style>') },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(false);
  });

  it("ignores whitespace differences", async () => {
    const plugin = new HtmlDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeHtmlExchange(200, "<div>Hello</div>") },
        { label: "false", exchange: makeHtmlExchange(200, "<div>  Hello  </div>\n") },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(false);
  });

  it("detects diff when actual content differs", async () => {
    const plugin = new HtmlDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeHtmlExchange(200, '<div class="results">Alice</div>') },
        { label: "false", exchange: makeHtmlExchange(200, '<div class="results">Bob</div>') },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(true);
  });

  it("ignores attribute value differences", async () => {
    const plugin = new HtmlDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeHtmlExchange(200, '<input name="csrf" value="abc123">') },
        { label: "false", exchange: makeHtmlExchange(200, '<input name="csrf" value="def456">') },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(false);
  });

  it("detects diff when attribute names differ", async () => {
    const plugin = new HtmlDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeHtmlExchange(200, '<input name="a" value="x">') },
        { label: "false", exchange: makeHtmlExchange(200, '<input name="a" placeholder="x">') },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(true);
  });

  it("skips non-HTML content type", async () => {
    const plugin = new HtmlDiffPlugin();
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
    const plugin = new HtmlDiffPlugin();
    await plugin.init({ commandBus, eventBus: new InMemoryEventBus(), logger: noopLogger });

    const result = await commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: makeHtmlExchange(200, "<div>Hello</div>") },
        { label: "false", exchange: makeHtmlExchange(500, "<div>Hello</div>") },
      ]),
    );

    expect(result.handled).toBe(true);
    expect(result.different).toBe(true);
  });
});
