import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { createJsonTamperPlugin } from "./json-tamper.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import type { HttpRequest, TamperInstruction } from "../../types/models.js";
import type { Brand, TamperMethod } from "../../types/branded.js";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeJsonPrimitiveInstruction(
  path: string[],
  originalValue: unknown,
  payload: string,
  method: TamperMethod,
): TamperInstruction {
  return {
    parameter: {
      type: "jsonPrimitive" as Brand<"jsonPrimitive", "ParameterType">,
      location: { path },
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

function makeJsonRequest(body: string): HttpRequest {
  return {
    method: "POST",
    url: "http://example.com/api",
    headers: { "content-type": "application/json" },
    body: Buffer.from(body, "utf-8"),
  };
}

describe("JsonTamperPlugin", () => {
  it("replaces nested JSON primitive value", async () => {
    const plugin = createJsonTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"user":{"name":"test"}}`);
    const instruction = makeJsonPrimitiveInstruction(
      ["user", "name"],
      "test",
      "INJECTED",
      "replaceValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.user.name).toBe("INJECTED");
    expect(result.url).toBe("http://example.com/api");
    expect(result.headers).toEqual({ "content-type": "application/json" });
  });

  it("appends payload to JSON primitive value", async () => {
    const plugin = createJsonTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"user":{"name":"test"}}`);
    const instruction = makeJsonPrimitiveInstruction(
      ["user", "name"],
      "test",
      "INJECTED",
      "appendValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.user.name).toBe("testINJECTED");
  });

  it("prepends payload to JSON primitive value", async () => {
    const plugin = createJsonTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"user":{"name":"test"}}`);
    const instruction = makeJsonPrimitiveInstruction(
      ["user", "name"],
      "test",
      "INJECTED",
      "prependValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.user.name).toBe("INJECTEDtest");
  });

  it("returns request unchanged when no JSON instructions", async () => {
    const plugin = createJsonTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"user":{"name":"test"}}`);
    const instruction: TamperInstruction = {
      parameter: {
        type: "query" as Brand<"query", "ParameterType">,
        location: { name: "foo" },
        originalValue: "bar",
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

  it("returns request unchanged when body is null", async () => {
    const plugin = createJsonTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/api",
      headers: { "content-type": "application/json" },
      body: null,
    };

    const instruction = makeJsonPrimitiveInstruction(
      ["name"],
      "test",
      "INJECTED",
      "replaceValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("handles multiple JSON instructions", async () => {
    const plugin = createJsonTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(
      `{"user":{"name":"test","email":"a@b.com"}}`,
    );
    const instructions = [
      makeJsonPrimitiveInstruction(
        ["user", "name"],
        "test",
        "X",
        "replaceValue" as TamperMethod,
      ),
      makeJsonPrimitiveInstruction(
        ["user", "email"],
        "a@b.com",
        "Y",
        "appendValue" as TamperMethod,
      ),
    ];

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, instructions),
    );

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.user.name).toBe("X");
    expect(parsed.user.email).toBe("a@b.comY");
  });

  it("handles jsonArray type instructions", async () => {
    const plugin = createJsonTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeJsonRequest(`{"items":["a","b"]}`);

    const instruction: TamperInstruction = {
      parameter: {
        type: "jsonArray" as Brand<"jsonArray", "ParameterType">,
        location: { path: ["items"] },
        originalValue: ["a", "b"],
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

    const parsed = JSON.parse((result.body as Buffer).toString("utf-8"));
    expect(parsed.items).toBe("INJECTED");
  });
});
