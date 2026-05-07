import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { FormParserPlugin, FormTamperPlugin } from "./form.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import type { HttpRequest, TamperInstruction } from "../../types/models.js";
import { FormParameter } from "../../types/models.js";
import type { Brand } from "../../types/branded.js";
import { TamperMethod, ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";

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

function flatParams(results: FormParameter[][]): FormParameter[] {
  return results.flat() as FormParameter[];
}

function makeFormInstruction(
  paramName: string,
  originalValue: string,
  payload: string,
  method: typeof TamperMethod,
): TamperInstruction<FormParameter> {
  return {
    parameter: new FormParameter(
      { name: paramName },
      originalValue,
      [ReplaceValue, AppendValue, PrependValue],
    ),
    payload: payload as Brand<string, "Payload">,
    method,
  };
}

describe("FormParserPlugin", () => {
  it("parses form URL-encoded body parameters", async () => {
    const plugin = new FormParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeFormRequest("username=admin&password=secret");
    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(2);
    expect(params).toEqual(
      expect.arrayContaining([
        new FormParameter(
          { name: "username" },
          "admin",
          [ReplaceValue, AppendValue, PrependValue],
        ),
        new FormParameter(
          { name: "password" },
          "secret",
          [ReplaceValue, AppendValue, PrependValue],
        ),
      ]),
    );
  });

  it("returns empty array when content-type is not form-urlencoded", async () => {
    const plugin = new FormParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/login",
      headers: { "content-type": "application/json" },
      body: Buffer.from("username=admin&password=secret", "utf-8"),
    };

    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(0);
  });

  it("returns empty array when body is null", async () => {
    const plugin = new FormParserPlugin();
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

    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(0);
  });

  it("handles content-type with charset parameter", async () => {
    const plugin = new FormParserPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request: HttpRequest = {
      method: "POST",
      url: "http://example.com/login",
      headers: { "content-type": "application/x-www-form-urlencoded; charset=UTF-8" },
      body: Buffer.from("key=value", "utf-8"),
    };

    const params = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(params).toHaveLength(1);
    expect(params[0].location).toEqual({ name: "key" });
    expect(params[0].originalValue).toBe("value");
  });
});

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
      ReplaceValue,
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
      AppendValue,
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
      PrependValue,
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
      ReplaceValue,
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
      ReplaceValue,
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
      ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

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
        ReplaceValue,
      ),
      makeFormInstruction(
        "password",
        "secret",
        "Y",
        AppendValue,
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
      ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyTamperCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });
});
