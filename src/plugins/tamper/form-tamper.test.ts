import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { FormTamperPlugin } from "./form-tamper.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import type { HttpRequest, TamperInstruction } from "../../types/models.js";
import type { Brand, TamperMethod } from "../../types/branded.js";
import { QueryParameterType } from "../parser/query-parser.js";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeFormRequest(body: string): HttpRequest {
  return {
    method: "POST",
    url: "http://example.com/login",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: Buffer.from(body, "utf-8"),
  };
}

function makeFormInstruction(
  paramName: string,
  originalValue: string,
  payload: string,
  method: TamperMethod,
): TamperInstruction {
  return {
    parameter: {
      type: QueryParameterType,
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

describe("FormTamperPlugin", () => {
  it("replaces form parameter value with payload", async () => {
    const plugin = new FormTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeFormRequest("username=admin");
    const instruction = makeFormInstruction(
      "username",
      "admin",
      "INJECTED",
      "replaceValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const body = (result.body as Buffer).toString("utf-8");
    const params = new URLSearchParams(body);
    expect(params.get("username")).toBe("INJECTED");
    expect(result.url).toBe("http://example.com/login");
    expect(result.headers).toEqual({
      "content-type": "application/x-www-form-urlencoded",
    });
  });

  it("appends payload to existing form parameter value", async () => {
    const plugin = new FormTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeFormRequest("username=admin");
    const instruction = makeFormInstruction(
      "username",
      "admin",
      "INJECTED",
      "appendValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const body = (result.body as Buffer).toString("utf-8");
    const params = new URLSearchParams(body);
    expect(params.get("username")).toBe("adminINJECTED");
  });

  it("prepends payload to existing form parameter value", async () => {
    const plugin = new FormTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeFormRequest("username=admin");
    const instruction = makeFormInstruction(
      "username",
      "admin",
      "INJECTED",
      "prependValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    const body = (result.body as Buffer).toString("utf-8");
    const params = new URLSearchParams(body);
    expect(params.get("username")).toBe("INJECTEDadmin");
  });

  it("returns request unchanged when content-type is not form-urlencoded", async () => {
    const plugin = new FormTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/login",
      headers: { "content-type": "application/json" },
      body: Buffer.from("username=admin", "utf-8"),
    };

    const instruction = makeFormInstruction(
      "username",
      "admin",
      "INJECTED",
      "replaceValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("returns request unchanged when instruction param is not in form body", async () => {
    const plugin = new FormTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeFormRequest("username=admin");
    const instruction = makeFormInstruction(
      "nonexistent",
      "value",
      "INJECTED",
      "replaceValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("does not tamper query string URL parameters", async () => {
    const plugin = new FormTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/login?redirect=home",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: Buffer.from("username=admin", "utf-8"),
    };

    const instruction = makeFormInstruction(
      "redirect",
      "home",
      "INJECTED",
      "replaceValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    // redirect is not in form body, so request should be unchanged
    expect(result).toEqual(request);
  });

  it("handles multiple form parameters", async () => {
    const plugin = new FormTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeFormRequest("username=admin&password=secret");
    const instructions = [
      makeFormInstruction(
        "username",
        "admin",
        "X",
        "replaceValue" as TamperMethod,
      ),
      makeFormInstruction(
        "password",
        "secret",
        "Y",
        "appendValue" as TamperMethod,
      ),
    ];

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, instructions),
    );

    const body = (result.body as Buffer).toString("utf-8");
    const params = new URLSearchParams(body);
    expect(params.get("username")).toBe("X");
    expect(params.get("password")).toBe("secretY");
  });

  it("returns request unchanged when body is null", async () => {
    const plugin = new FormTamperPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/login",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: null,
    };

    const instruction = makeFormInstruction(
      "username",
      "admin",
      "INJECTED",
      "replaceValue" as TamperMethod,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });
});
