import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { PluginRegistryImpl } from "../../core/plugin.ts";
import { SqliDiffPlugin } from "./sqli-diff.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type {
  AuditParameter,
  HttpRequest,
  JsonPrimitive,
  Finding,
  Scenario,
} from "../../types/models.ts";
import { ReplayResult, BuiltinMutationType } from "../../types/models.ts";
import { QueryParameter } from "../parameter/query.ts";
import { JsonPrimitiveParameter } from "../parameter/json.ts";
import {
  ExchangeId,
  ScenarioId,
  ScenarioType,
} from "../../types/branded.ts";
import type { AuditItem } from "../../core/audit-item.ts";
import { ExactDiffPlugin } from "../diff/exact.ts";
import { JsonDiffPlugin } from "../diff/json.ts";

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
let registry: PluginRegistryImpl;
const noopLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
  registry = new PluginRegistryImpl();
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

const mockRequest: HttpRequest = {
  method: "GET",
  url: "http://test.com",
  headers: {},
  body: null,
};

async function setupPlugins() {
  const diffPlugin = new ExactDiffPlugin();
  const jsonPlugin = new JsonDiffPlugin();
  const sqliPlugin = new SqliDiffPlugin();
  registry.register(diffPlugin);
  registry.register(jsonPlugin);
  registry.register(sqliPlugin);
  await diffPlugin.init({
    commandBus,
    eventBus: new InMemoryEventBus(),
    logger: noopLogger,
    pluginRegistry: registry,
  });
  await jsonPlugin.init({
    commandBus,
    eventBus: new InMemoryEventBus(),
    logger: noopLogger,
    pluginRegistry: registry,
  });
  await sqliPlugin.init({
    commandBus,
    eventBus: new InMemoryEventBus(),
    logger: noopLogger,
    pluginRegistry: registry,
  });
}

describe("SqliDiffPlugin", () => {
  it("creates definitions only for parameters with AppendValue tamper", async () => {
    await setupPlugins();

    const targets = [
      makeQueryParameter("id", "1"),
      makeJsonPrimitiveParam(["user", "id"], 1),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results.find((r) => r.length > 0) ?? [];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("signature:sqli-diff");
  });

  it("detects SQL injection when responses differ via diff judgment", async () => {
    await setupPlugins();

    const parameter = makeQueryParameter("id", "1");
    let callCount = 0;
    const mockReplay = async () => {
      callCount++;
      const body =
        callCount === 1 ? '{"id":1,"name":"Alice"}' : '{"id":0,"name":null}';
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
        signatureName: "signature:sqli-diff",
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
    expect(finding.evidence.judgmentId).toBe("diff-based");
    expect(finding.evidence.evidenceExchanges).toHaveLength(2);
  });

  it("does not report vulnerability when responses are identical", async () => {
    await setupPlugins();

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
        signatureName: "signature:sqli-diff",
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
    expect(finding.evidence.evidenceExchanges).toHaveLength(2);
  });

  it("uses the diffStrategy from RunAuditContext to pick the diff plugin", async () => {
    await setupPlugins();

    const parameter = makeQueryParameter("id", "1");
    let callCount = 0;
    // Both responses are structurally equivalent JSON (same keys, different values)
    // so json strategy returns different=false, while exact strategy would return different=true.
    const mockReplay = async () => {
      callCount++;
      const body =
        callCount === 1 ? '{"id":1,"name":"Alice"}' : '{"id":2,"name":"Bob"}';
      return new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: { "content-type": "text/plain" },
          body: Buffer.from(body),
        },
      });
    };

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:sqli-diff",
        scenario: makeScenario({ diffStrategy: { type: "json" } }),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as {
      status: "completed";
      finding: Finding;
    };

    // json diff sees the same structure, so different=false, even though exact bytes differ.
    expect(finding.vulnerable).toBe(false);
  });
});
