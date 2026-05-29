import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { OsCommandInjectionPlugin } from "./os-command-injection.ts";
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
import { ExchangeId, ScenarioId, SignatureId } from "../../types/branded.ts";
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

describe("OsCommandInjectionPlugin", () => {
  it("creates definitions only for parameters with AppendValue mutation", async () => {
    const plugin = new OsCommandInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeQueryParameter("host", "localhost"),
      makeJsonPrimitiveParam(["cmd"], "ls"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("os-command-injection");
    expect(items[0].parameter).toEqual(targets[0]);
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new OsCommandInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeJsonPrimitiveParam(["cmd"], "ls"),
      makeHeaderTarget("Authorization", "Bearer token"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(0);
  });

  it("detects command output marker in response body", async () => {
    const plugin = new OsCommandInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("host", "localhost");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: Buffer.from("ping statistics ---\ngevanni_cm7j\n--- "),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("os-command-injection"),
        scenarioId: ScenarioId("test-scenario"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );

    const { finding } = findings[0] as { status: "completed"; finding: Finding };
    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence.judgmentId).toBe("command-output-reflection");
    expect(finding.evidence.evidenceExchanges).toHaveLength(1);
  });

  it("does not report vulnerability when marker is not in response", async () => {
    const plugin = new OsCommandInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("host", "localhost");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: Buffer.from("normal response without command output"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("os-command-injection"),
        scenarioId: ScenarioId("test-scenario"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );

    const { finding } = findings[0] as { status: "completed"; finding: Finding };
    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence.judgmentId).toBe("command-output-reflection");
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("handles null response body", async () => {
    const plugin = new OsCommandInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("host", "localhost");
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
        signatureName: SignatureId("os-command-injection"),
        scenarioId: ScenarioId("test-scenario"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );

    const { finding } = findings[0] as { status: "completed"; finding: Finding };
    expect(finding.vulnerable).toBe(false);
  });
});
