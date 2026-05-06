import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { FormParserPlugin } from "./form-parser.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import type { HttpRequest } from "../../types/models.js";
import { ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";
import { FormParameterType } from "./form-parser.js";
import type { FormParameter } from "./form-parser.js";

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
        {
          type: FormParameterType,
          location: { name: "username" },
          originalValue: "admin",
          allowedTampers: [
            ReplaceValue,
            AppendValue,
            PrependValue,
          ],
        },
        {
          type: FormParameterType,
          location: { name: "password" },
          originalValue: "secret",
          allowedTampers: [
            ReplaceValue,
            AppendValue,
            PrependValue,
          ],
        },
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
