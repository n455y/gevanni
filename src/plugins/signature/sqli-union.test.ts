import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { SqliUnionPlugin, UNION_PAYLOADS } from "./sqli-union.ts";
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
import {
  ExchangeId,
  ScenarioId,

} from "../../types/branded.ts";
import type { AuditItem } from "../../core/audit-item.ts";

let commandBus: InMemoryCommandBus;
const noopLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeQueryParameter(name: string, value: string): AuditParameter {
  return new QueryParameter({ name }, value, [BuiltinMutationType.AppendValue]);
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

describe("SqliUnionPlugin", () => {
  it("creates definitions only for parameters with AppendValue tamper", async () => {
    const plugin = new SqliUnionPlugin();
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
    expect(items[0].signatureName).toBe("signature:sqli-union");
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new SqliUnionPlugin();
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

  it("detects union-based injection when marker appears in response", async () => {
    const plugin = new SqliUnionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    let callCount = 0;
    const mockReplay = async () => {
      callCount++;
      const hasMarker = callCount === 3;
      return new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from(
            hasMarker
              ? `row1 gevanni_union_ extra data`
              : "normal response without injection",
          ),
        },
      });
    };

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:sqli-union",
        scenarioId: ScenarioId("test-scenario"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as {
      status: "completed";
      finding: Finding;
    };

    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence.judgmentId).toBe("union-based-marker");
    expect(finding.evidence.evidenceExchanges).toHaveLength(1);
  });

  it("does not report vulnerability when marker never appears", async () => {
    const plugin = new SqliUnionPlugin();
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
          body: Buffer.from("normal response"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:sqli-union",
        scenarioId: ScenarioId("test-scenario"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as {
      status: "completed";
      finding: Finding;
    };

    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("stops testing payloads after first match", async () => {
    const plugin = new SqliUnionPlugin();
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
          statusCode: 200,
          headers: {},
          body: Buffer.from("gevanni_union_ found"),
        },
      });
    };

    await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:sqli-union",
        scenarioId: ScenarioId("test-scenario"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );

    expect(callCount).toBe(1);
  });

  it("generates payloads for 1 to 10 columns", () => {
    expect(UNION_PAYLOADS).toHaveLength(10);
    expect(UNION_PAYLOADS[0]).toBe("' UNION SELECT 'gevanni_union_'--");
    expect(UNION_PAYLOADS[1]).toBe("' UNION SELECT 'gevanni_union_',NULL--");
    expect(UNION_PAYLOADS[9]).toContain(
      "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL",
    );
  });
});
