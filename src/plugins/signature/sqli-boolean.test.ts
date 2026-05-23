import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { SqliBooleanPlugin } from "./sqli-boolean.ts";
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

describe("SqliBooleanPlugin", () => {
  it("creates definitions only for parameters with AppendValue tamper", async () => {
    const plugin = new SqliBooleanPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeQueryParameter("id", "1"),
      makeJsonPrimitiveParam(["user", "id"], 1),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe(SignatureId("sqli-boolean"));
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new SqliBooleanPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeJsonPrimitiveParam(["user", "id"], 1),
      makeHeaderTarget("Authorization", "Bearer token"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(0);
  });

  it("detects boolean-based injection when responses differ", async () => {
    const plugin = new SqliBooleanPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    let callCount = 0;
    const mockReplay = async () => {
      callCount++;
      const body =
        callCount === 1
          ? '{"id":1,"name":"Alice"}'
          : '{"id":0,"name":null}';
      return new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from(body),
        },
      });
    };

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-boolean"),
        parameter,
        replay: mockReplay,
      }),
    );
    const finding = findings[0] as Finding;

    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence.judgmentId).toBe("boolean-based-differential");
    expect(finding.evidence.evidenceExchanges).toHaveLength(2);
  });

  it("detects boolean-based injection when status codes differ", async () => {
    const plugin = new SqliBooleanPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    let callCount = 0;
    const mockReplay = async () => {
      callCount++;
      return new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: callCount === 1 ? 200 : 500,
          headers: {},
          body: Buffer.from("same body"),
        },
      });
    };

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-boolean"),
        parameter,
        replay: mockReplay,
      }),
    );
    const finding = findings[0] as Finding;

    expect(finding.vulnerable).toBe(true);
  });

  it("does not report vulnerability when responses are identical", async () => {
    const plugin = new SqliBooleanPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from("same response"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-boolean"),
        parameter,
        replay: mockReplay,
      }),
    );
    const finding = findings[0] as Finding;

    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("handles null response bodies", async () => {
    const plugin = new SqliBooleanPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    const mockReplay = async () =>
      new ReplayResult({
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
        signatureName: SignatureId("sqli-boolean"),
        parameter,
        replay: mockReplay,
      }),
    );
    const finding = findings[0] as Finding;

    expect(finding.vulnerable).toBe(false);
  });
});
