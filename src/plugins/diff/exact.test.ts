import { describe, it, expect } from "vitest";
import { ExactDiffPlugin } from "./exact.ts";
import { ExchangeId } from "../../types/branded.ts";

function makeExchange(statusCode: number, body: string) {
  return {
    id: ExchangeId("test-exchange-id"),
    request: { method: "GET", url: "http://test.com", headers: {}, body: null },
    response: { statusCode, headers: {}, body: Buffer.from(body) },
  };
}

describe("ExactDiffPlugin", () => {
  const plugin = new ExactDiffPlugin();

  it("detects vulnerability when response bodies differ", () => {
    const result = plugin.compare(
      makeExchange(200, '{"id":1}'),
      makeExchange(200, '{"id":0}'),
    );

    expect(result.hasDifferent).toBe(true);
  });

  it("detects diff when status codes differ", () => {
    const result = plugin.compare(
      makeExchange(200, "same"),
      makeExchange(500, "same"),
    );

    expect(result.hasDifferent).toBe(true);
  });

  it("returns not vulnerable when responses are identical", () => {
    const result = plugin.compare(
      makeExchange(200, "same"),
      makeExchange(200, "same"),
    );

    expect(result.hasDifferent).toBe(false);
  });
});
