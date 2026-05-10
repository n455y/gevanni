import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { ReflectedXssPlugin } from "./reflected-xss.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type {
  AuditTarget,
  HttpRequest,
  JsonPrimitive,
  Finding,
} from "../../types/models.ts";
import { QueryParameter } from "../parameter/query.ts";
import { FormParameter } from "../parameter/form.ts";
import { JsonPrimitiveParameter } from "../parameter/json.ts";
import { HeaderParameter } from "../parameter/header.ts";
import { ReplaceValue, AppendValue } from "../../types/branded.ts";
import type { AuditItem } from "../../core/audit-item.ts";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeQueryTarget(name: string, value: string): AuditTarget {
  return new QueryParameter({ name }, value, [ReplaceValue, AppendValue]);
}

function makeJsonPrimitiveParam(
  path: string[],
  value: unknown,
): AuditTarget {
  return new JsonPrimitiveParameter({ path }, value as JsonPrimitive, [
    ReplaceValue,
  ]);
}

function makeFormTarget(name: string, value: string): AuditTarget {
  return new FormParameter({ name }, value, [ReplaceValue, AppendValue]);
}

function makeHeaderTarget(name: string, value: string): AuditTarget {
  return new HeaderParameter({ name }, value, [ReplaceValue]);
}

const mockRequest: HttpRequest = {
  method: "GET",
  url: "http://test.com",
  headers: {},
  body: null,
};

describe("ReflectedXssPlugin", () => {
  it("creates definitions only for parameters with AppendValue tamper", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const targets = [
      makeQueryTarget("q", "search"),
      makeJsonPrimitiveParam(["user", "name"], "test"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("reflected-xss");
    expect(items[0].target).toEqual(targets[0]);
  });

  it("creates definitions for form parameters", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const targets = [makeFormTarget("username", "admin")];
    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].target).toEqual(targets[0]);
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const targets = [makeHeaderTarget("Authorization", "Bearer token")];
    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(0);
  });

  it("detects reflected payload in response body", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const target = makeQueryTarget("q", "search");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: Buffer.from("some response with <script>alert(1)</script> in it"),
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunAuditCommand({
        signatureName: "reflected-xss",
        target,
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence).toContain("reflected in response body");
    expect(finding.request).toEqual(mockRequest);
  });

  it("does not report vulnerability when payload is not reflected", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const target = makeQueryTarget("q", "search");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: Buffer.from("safe response without any script tags"),
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunAuditCommand({
        signatureName: "reflected-xss",
        target,
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence).toContain("not reflected");
  });

  it("handles null response body", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const target = makeQueryTarget("q", "search");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: null,
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunAuditCommand({
        signatureName: "reflected-xss",
        target,
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence).toContain("not reflected");
  });
});
