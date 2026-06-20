import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { ReflectedXssPlugin } from "./reflected-xss.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type {
  AuditParameter,
  HttpRequest,
  JsonPrimitive,
  Finding,
  Exchange,
  Scenario,
} from "../../types/models.ts";
import { ReplayResult, BuiltinMutationType } from "../../types/models.ts";
import { QueryParameter } from "../parameter/query.ts";
import { FormParameter } from "../parameter/form.ts";
import { JsonPrimitiveParameter } from "../parameter/json.ts";
import { HeaderParameter } from "../parameter/header.ts";
import {
  ExchangeId,
  ScenarioId,
  ScenarioType,
} from "../../types/branded.ts";
import type { AuditItem } from "../../core/audit-item.ts";

function makeScenario(overrides: Partial<Scenario> = {}): Scenario {
  return {
    id: ScenarioId("test-scenario"),
    name: "Test Scenario",
    type: ScenarioType("test"),
    source: null,
    representation: "Test Scenario",
    diffStrategy: { type: "exact" },
    ...overrides,
  };
}

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

function makeFormTarget(name: string, value: string): AuditParameter {
  return new FormParameter({ name }, value, [
    BuiltinMutationType.ReplaceValue,
    BuiltinMutationType.AppendValue,
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

describe("ReflectedXssPlugin", () => {
  it("creates definitions only for parameters with StandardMutationType.AppendValue tamper", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeQueryParameter("q", "search"),
      makeJsonPrimitiveParam(["user", "name"], "test"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("signature:reflected-xss");
    expect(items[0].parameter).toEqual(targets[0]);
  });

  it("creates definitions for form parameters", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [makeFormTarget("username", "admin")];
    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].parameter).toEqual(targets[0]);
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
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
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "search");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from(
            "some response with <script>alert(1)</script> in it",
          ),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:reflected-xss",
        scenario: makeScenario(),
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
    expect(finding.evidence.judgmentId).toBe("payload-reflection");
    expect(finding.evidence.evidenceExchanges).toHaveLength(1);
    expect(finding.request).toEqual(mockRequest);
  });

  it("does not report vulnerability when payload is not reflected", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "search");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from("safe response without any script tags"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:reflected-xss",
        scenario: makeScenario(),
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
    expect(finding.evidence.judgmentId).toBe("payload-reflection");
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("handles null response body", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "search");
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
        signatureName: "signature:reflected-xss",
        scenario: makeScenario(),
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
    expect(finding.evidence.judgmentId).toBe("payload-reflection");
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });
});
