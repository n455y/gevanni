import { describe, it, expect } from "vitest";
import { HtmlDiffPlugin } from "./html.ts";
import { ExchangeId } from "../../types/branded.ts";

function makeHtmlExchange(statusCode: number, body: string) {
  return {
    id: ExchangeId("test-exchange-id"),
    request: { method: "GET", url: "http://test.com", headers: {}, body: null },
    response: {
      statusCode,
      headers: { "content-type": "text/html" },
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

describe("HtmlDiffPlugin", () => {
  const plugin = new HtmlDiffPlugin();

  it("ignores script tag difference", () => {
    const result = plugin.compare(
      makeHtmlExchange(200, "<div>Hello</div><script>var x=1;</script>"),
      makeHtmlExchange(200, "<div>Hello</div><script>var x=2;</script>"),
    );

    expect(result.hasDifferent).toBe(false);
  });

  it("ignores style tag difference", () => {
    const result = plugin.compare(
      makeHtmlExchange(200, "<div>Hello</div><style>.a{color:red;}</style>"),
      makeHtmlExchange(200, "<div>Hello</div><style>.a{color:blue;}</style>"),
    );

    expect(result.hasDifferent).toBe(false);
  });

  it("ignores whitespace differences", () => {
    const result = plugin.compare(
      makeHtmlExchange(200, "<div>Hello</div>"),
      makeHtmlExchange(200, "<div>  Hello  </div>\n"),
    );

    expect(result.hasDifferent).toBe(false);
  });

  it("detects diff when actual content differs", () => {
    const result = plugin.compare(
      makeHtmlExchange(200, '<div class="results">Alice</div>'),
      makeHtmlExchange(200, '<div class="results">Bob</div>'),
    );

    expect(result.hasDifferent).toBe(true);
  });

  it("ignores attribute value differences", () => {
    const result = plugin.compare(
      makeHtmlExchange(200, '<input name="csrf" value="abc123">'),
      makeHtmlExchange(200, '<input name="csrf" value="def456">'),
    );

    expect(result.hasDifferent).toBe(false);
  });

  it("detects diff when attribute names differ", () => {
    const result = plugin.compare(
      makeHtmlExchange(200, '<input name="a" value="x">'),
      makeHtmlExchange(200, '<input name="a" placeholder="x">'),
    );

    expect(result.hasDifferent).toBe(true);
  });

  it("returns not different for non-HTML content type", () => {
    const result = plugin.compare(
      makeExchange(200, "hello"),
      makeExchange(200, "world"),
    );

    expect(result.hasDifferent).toBe(false);
  });

  it("detects diff when status codes differ", () => {
    const result = plugin.compare(
      makeHtmlExchange(200, "<div>Hello</div>"),
      makeHtmlExchange(500, "<div>Hello</div>"),
    );

    expect(result.hasDifferent).toBe(true);
  });
});
