import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { createQueryTamperPlugin } from "./query-tamper.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import type { HttpRequest, TamperInstruction } from "../../types/models.js";
import type { Brand, TamperMethod } from "../../types/branded.js";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeQueryInstruction(
  paramName: string,
  originalValue: string,
  payload: string,
  method: TamperMethod,
): TamperInstruction {
  return {
    parameter: {
      type: "query" as Brand<"query", "ParameterType">,
      location: { name: paramName },
      originalValue,
      allowedTampers: [
        "replaceValue" as TamperMethod,
        "appendValue" as TamperMethod,
        "prependValue" as TamperMethod,
      ],
    },
    payload: payload as Brand<string, "Payload">,
    method,
  };
}

describe("QueryTamperPlugin", () => {
  it("replaces query parameter value with payload", async () => {
    const plugin = createQueryTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?foo=bar",
      headers: {},
      body: null,
    };

    const instruction = makeQueryInstruction(
      "foo",
      "bar",
      "INJECTED",
      "replaceValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("INJECTED");
    expect(result.method).toBe("GET");
    expect(result.headers).toEqual({});
    expect(result.body).toBeNull();
  });

  it("appends payload to existing query parameter value", async () => {
    const plugin = createQueryTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?foo=bar",
      headers: {},
      body: null,
    };

    const instruction = makeQueryInstruction(
      "foo",
      "bar",
      "INJECTED",
      "appendValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("barINJECTED");
  });

  it("prepends payload to existing query parameter value", async () => {
    const plugin = createQueryTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?foo=bar",
      headers: {},
      body: null,
    };

    const instruction = makeQueryInstruction(
      "foo",
      "bar",
      "INJECTED",
      "prependValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("INJECTEDbar");
  });

  it("returns request unchanged when no query instructions", async () => {
    const plugin = createQueryTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?foo=bar",
      headers: {},
      body: null,
    };

    const instruction: TamperInstruction = {
      parameter: {
        type: "jsonPrimitive" as Brand<"jsonPrimitive", "ParameterType">,
        location: { path: ["user", "name"] },
        originalValue: "test",
        allowedTampers: [
          "replaceValue" as TamperMethod,
          "appendValue" as TamperMethod,
          "prependValue" as TamperMethod,
        ],
      },
      payload: "INJECTED" as Brand<string, "Payload">,
      method: "replaceValue" as TamperMethod,
    };

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("handles multiple query parameters", async () => {
    const plugin = createQueryTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "GET",
      url: "http://example.com?foo=bar&baz=123",
      headers: {},
      body: null,
    };

    const instructions = [
      makeQueryInstruction("foo", "bar", "X", "replaceValue" as TamperMethod),
      makeQueryInstruction("baz", "123", "Y", "appendValue" as TamperMethod),
    ];

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, instructions),
    );

    const resultUrl = new URL(result.url);
    expect(resultUrl.searchParams.get("foo")).toBe("X");
    expect(resultUrl.searchParams.get("baz")).toBe("123Y");
  });
});
