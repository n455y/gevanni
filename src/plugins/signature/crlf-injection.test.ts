import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { CrlfInjectionPlugin } from "./crlf-injection.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type {
  AuditParameter,
  HttpRequest,
  JsonPrimitive,
  Finding,
} from "../../types/models.ts";
import { ReplayResult, BuiltinMutationType } from "../../types/models.ts";
import { QueryParameter } from "../parameter/query.ts";
import { JsonPrimitiveParameter } from "../parameter/json.ts";
import { HeaderParameter } from "../parameter/header.ts";
import { ExchangeId, SignatureId } from "../../types/branded.ts";
import type { AuditItem } from "../../core/audit-item.ts";

let commandBus: InMemoryCommandBus;
const noopLogger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeQueryParameter(name: string, value: string): AuditParameter {
  return new QueryParameter({ name }, value, [
    BuiltinMutationType.ReplaceValue,
    BuiltinMutationType.AppendValue,
  ]);
}

function makeJsonPrimitiveParam(
  path: string[],
  value: unknown,
): AuditParameter {
  return new JsonPrimitiveParameter({ path }, value as JsonPrimitive, [
    BuiltinMutationType.ReplaceValue,
  ]);
}

function makeHeaderTarget(name: string, value: string): AuditParameter {
  return new HeaderParameter({ name }, value, [
    BuiltinMutationType.ReplaceValue,
  ]);
}

const mockRequest: HttpRequest = {
  method: "GET",
  url: "http://test.com",
  headers: {},
  body: null,
};

describe("CrlfInjectionPlugin", () => {
  it("creates definitions only for parameters with AppendValue mutation", async () => {
    const plugin = new CrlfInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeQueryParameter("url", "/page"),
      makeJsonPrimitiveParam(["redirect"], "/home"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("crlf-injection");
    expect(items[0].parameter).toEqual(targets[0]);
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new CrlfInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeJsonPrimitiveParam(["redirect"], "/home"),
      makeHeaderTarget("Authorization", "Bearer token"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(0);
  });

  it("detects injected header in response headers", async () => {
    const plugin = new CrlfInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("url", "/page");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: { "X-Injected": "gevanni_crlf" },
        body: Buffer.from("normal response"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("crlf-injection"),
        parameter,
        replay: mockReplay,
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence.judgmentId).toBe("header-injection");
    expect(finding.evidence.evidenceExchanges).toHaveLength(1);
  });

  it("detects injected header value in existing response header", async () => {
    const plugin = new CrlfInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("url", "/page");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 302,
        headers: { "Location": "/page\r\nX-Injected: gevanni_crlf" },
        body: Buffer.from(""),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("crlf-injection"),
        parameter,
        replay: mockReplay,
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(true);
  });

  it("does not report vulnerability when marker is not in response headers", async () => {
    const plugin = new CrlfInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("url", "/page");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: { "Content-Type": "text/html" },
        body: Buffer.from("normal response without injected headers"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("crlf-injection"),
        parameter,
        replay: mockReplay,
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence.judgmentId).toBe("header-injection");
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("handles null response body", async () => {
    const plugin = new CrlfInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("url", "/page");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: null,
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("crlf-injection"),
        parameter,
        replay: mockReplay,
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(false);
  });
});
