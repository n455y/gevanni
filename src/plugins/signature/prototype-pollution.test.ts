import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import {
  PrototypePollutionPlugin,
  PROTOTYPE_POLLUTION_PATTERNS,
} from "./prototype-pollution.ts";
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

describe("PrototypePollutionPlugin", () => {
  it("creates definitions only for parameters with AppendValue mutation", async () => {
    const plugin = new PrototypePollutionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeQueryParameter("q", "test"),
      makeJsonPrimitiveParam(["filter"], "all"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("signature:prototype-pollution");
    expect(items[0].parameter).toEqual(targets[0]);
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new PrototypePollutionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeJsonPrimitiveParam(["filter"], "all"),
      makeHeaderTarget("Authorization", "Bearer token"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(0);
  });

  it("detects prototype pollution error in response body", async () => {
    const plugin = new PrototypePollutionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 500,
          headers: {},
          body: Buffer.from(
            "TypeError: Cannot set property 'isAdmin' of undefined",
          ),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:prototype-pollution",
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
    expect(finding.evidence.judgmentId).toBe("prototype-pollution-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(1);
  });

  it("detects maximum call stack error in response body", async () => {
    const plugin = new PrototypePollutionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 500,
          headers: {},
          body: Buffer.from("RangeError: Maximum call stack size exceeded"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:prototype-pollution",
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
  });

  it("does not report vulnerability when no prototype pollution error in response", async () => {
    const plugin = new PrototypePollutionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from("normal response with no errors"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:prototype-pollution",
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
    expect(finding.evidence.judgmentId).toBe("prototype-pollution-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("handles null response body", async () => {
    const plugin = new PrototypePollutionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
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
        signatureName: "signature:prototype-pollution",
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
  });

  it("includes all required prototype pollution patterns", () => {
    expect(PROTOTYPE_POLLUTION_PATTERNS).toHaveLength(6);
    expect(
      PROTOTYPE_POLLUTION_PATTERNS[0].test(
        "Cannot set property 'x' of undefined",
      ),
    ).toBe(true);
    expect(
      PROTOTYPE_POLLUTION_PATTERNS[1].test("Object.prototype.hasOwnProperty"),
    ).toBe(true);
    expect(
      PROTOTYPE_POLLUTION_PATTERNS[2].test(
        "TypeError: config.trim is not a function",
      ),
    ).toBe(true);
    expect(
      PROTOTYPE_POLLUTION_PATTERNS[3].test("JSON.parse: unexpected character"),
    ).toBe(true);
    expect(
      PROTOTYPE_POLLUTION_PATTERNS[4].test("Maximum call stack size exceeded"),
    ).toBe(true);
    expect(
      PROTOTYPE_POLLUTION_PATTERNS[5].test("RangeError: Maximum call stack"),
    ).toBe(true);
  });
});
