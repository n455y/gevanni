import { beforeEach, describe, expect, it } from "vitest";
import { ApplyMutationCommand } from "../../commands/mutation.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import type { MutationType } from "../../types/branded.ts";
import { AuditParameter, type HttpRequest, BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import {
  FormMutation,
  FormMutationPlugin,
  FormParameter,
  FormParserPlugin,
} from "./form.ts";

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

function flatParams(results: AuditParameter[][]): AuditParameter[] {
  return results.flat();
}

function makeFormInstruction(
  paramName: string,
  originalValue: string,
  payload: string,
  method: MutationType,
): FormMutation {
  return new FormMutation(
    new FormParameter({ name: paramName }, originalValue, [
      BuiltinMutationType.ReplaceValue,
      BuiltinMutationType.AppendValue,
      BuiltinMutationType.PrependValue,
    ]),
    BuiltinPayload.String(payload),
    method,
  );
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
    const targets = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(2);
    expect(targets).toEqual(
      expect.arrayContaining([
        new FormParameter({ name: "username" }, "admin", [
          BuiltinMutationType.ReplaceValue,
          BuiltinMutationType.AppendValue,
          BuiltinMutationType.PrependValue,
        ]),
        new FormParameter({ name: "password" }, "secret", [
          BuiltinMutationType.ReplaceValue,
          BuiltinMutationType.AppendValue,
          BuiltinMutationType.PrependValue,
        ]),
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

    const targets = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
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

    const targets = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(0);
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
      headers: {
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
      },
      body: Buffer.from("key=value", "utf-8"),
    };

    const targets = flatParams(
      await commandBus.broadcast(new ParseRequestCommand(request)),
    );

    expect(targets).toHaveLength(1);
    expect(targets[0].location).toEqual({ name: "key" });
    expect(targets[0].originalValue).toBe("value");
  });
});

describe("FormMutationPlugin", () => {
  it("replaces form parameter value with payload", async () => {
    const plugin = new FormMutationPlugin();
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
      BuiltinMutationType.ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const body = (result.body as Buffer).toString("utf-8");
    const targets = new URLSearchParams(body);
    expect(targets.get("username")).toBe("INJECTED");
    expect(result.url).toBe("http://example.com/login");
    expect(result.headers).toEqual({
      "content-type": "application/x-www-form-urlencoded",
    });
  });

  it("appends payload to existing form parameter value", async () => {
    const plugin = new FormMutationPlugin();
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
      BuiltinMutationType.AppendValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const body = (result.body as Buffer).toString("utf-8");
    const targets = new URLSearchParams(body);
    expect(targets.get("username")).toBe("adminINJECTED");
  });

  it("prepends payload to existing form parameter value", async () => {
    const plugin = new FormMutationPlugin();
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
      BuiltinMutationType.PrependValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    const body = (result.body as Buffer).toString("utf-8");
    const targets = new URLSearchParams(body);
    expect(targets.get("username")).toBe("INJECTEDadmin");
  });

  it("returns request unchanged when content-type is not form-urlencoded", async () => {
    const plugin = new FormMutationPlugin();
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
      BuiltinMutationType.ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("returns request unchanged when instruction param is not in form body", async () => {
    const plugin = new FormMutationPlugin();
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
      BuiltinMutationType.ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("does not tamper query string URL parameters", async () => {
    const plugin = new FormMutationPlugin();
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
      BuiltinMutationType.ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });

  it("handles multiple form parameters", async () => {
    const plugin = new FormMutationPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const request = makeFormRequest("username=admin&password=secret");
    const mutations = [
      makeFormInstruction(
        "username",
        "admin",
        "X",
        BuiltinMutationType.ReplaceValue,
      ),
      makeFormInstruction(
        "password",
        "secret",
        "Y",
        BuiltinMutationType.AppendValue,
      ),
    ];

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, mutations),
    );

    const body = (result.body as Buffer).toString("utf-8");
    const targets = new URLSearchParams(body);
    expect(targets.get("username")).toBe("X");
    expect(targets.get("password")).toBe("secretY");
  });

  it("returns request unchanged when body is null", async () => {
    const plugin = new FormMutationPlugin();
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
      BuiltinMutationType.ReplaceValue,
    );

    const result = await commandBus.pipe(
      new ApplyMutationCommand(request, [instruction]),
    );

    expect(result).toEqual(request);
  });
});
