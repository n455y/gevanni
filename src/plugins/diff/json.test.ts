import { describe, it, expect } from "vitest";
import { JsonDiffPlugin } from "./json.ts";
import { ExchangeId } from "../../types/branded.ts";

function makeJsonExchange(statusCode: number, body: string) {
  return {
    id: ExchangeId("test-exchange-id"),
    request: { method: "GET", url: "http://test.com", headers: {}, body: null },
    response: {
      statusCode,
      headers: { "content-type": "application/json" },
      body: Buffer.from(body),
    },
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
  const plugin = new JsonDiffPlugin();

  it("detects diff when value changes but structure is same", () => {
    const result = plugin.compare(
      makeJsonExchange(200, '{"id":1,"name":"Alice"}'),
      makeJsonExchange(200, '{"id":2,"name":"Bob"}'),
    );

    expect(result.hasDifferent).toBe(false);
  });

  it("detects diff when structure differs", () => {
    const result = plugin.compare(
      makeJsonExchange(200, '{"id":1,"name":"Alice"}'),
      makeJsonExchange(200, '{"id":1}'),
    );

    expect(result.hasDifferent).toBe(true);
  });

  it("detects diff when array length differs", () => {
    const result = plugin.compare(
      makeJsonExchange(200, '{"items":[{"id":1},{"id":2}]}'),
      makeJsonExchange(200, '{"items":[{"id":1}]}'),
    );

    expect(result.hasDifferent).toBe(true);
  });

  it("returns not different for non-JSON content type", () => {
    const result = plugin.compare(
      makeExchange(200, "hello"),
      makeExchange(200, "world"),
    );

    expect(result.hasDifferent).toBe(false);
  });

  it("detects diff when status codes differ", () => {
    const result = plugin.compare(
      makeJsonExchange(200, '{"id":1}'),
      makeJsonExchange(500, '{"id":1}'),
    );

    expect(result.hasDifferent).toBe(true);
  });

  it("handles same structure with nested objects", () => {
    const result = plugin.compare(
      makeJsonExchange(200, '{"user":{"id":1,"name":"Alice"},"ts":123}'),
      makeJsonExchange(200, '{"user":{"id":2,"name":"Bob"},"ts":456}'),
    );

    expect(result.hasDifferent).toBe(false);
  });
});
