import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { PluginRegistryImpl } from "../../core/plugin.ts";
import ExactDiffPlugin from "../diff/exact.ts";
import HppPlugin from "./hpp.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type {
  AuditParameter,
  HttpRequest,
  Finding,
  Scenario,
} from "../../types/models.ts";
import { ReplayResult, BuiltinMutationType } from "../../types/models.ts";
import { QueryParameter } from "../parameter/query/model.ts";
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
  registry.register(new ExactDiffPlugin());
});

async function initPlugin(plugin: HppPlugin) {
  await plugin.init({
    commandBus,
    eventBus: new InMemoryEventBus(),
    logger: noopLogger,
    pluginRegistry: registry,
  });
}

function makeQueryParameter(name: string, value: string): AuditParameter {
  return new QueryParameter({ name }, value, [
    BuiltinMutationType.ReplaceValue,
    BuiltinMutationType.AppendValue,
  ]);
}

const mockRequest: HttpRequest = {
  method: "GET",
  url: "http://test.com",
  headers: {},
  body: null,
};

describe("HppPlugin", () => {
  it("creates definitions only for parameters with AppendValue mutation", async () => {
    const plugin = new HppPlugin();
    await initPlugin(plugin);

    const targets = [
      makeQueryParameter("id", "1"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("signature:hpp");
  });

  it("does not create definitions for non-AppendValue parameters", async () => {
    const plugin = new HppPlugin();
    await initPlugin(plugin);

    const targets = [
      new QueryParameter({ name: "q" }, "test", [
        BuiltinMutationType.ReplaceValue,
      ]),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(0);
  });

  it("detects HPP via status code change", async () => {
    const plugin = new HppPlugin();
    await initPlugin(plugin);

    const parameter = makeQueryParameter("id", "1");
    let callCount = 0;
    const mockReplay = async () => {
      callCount++;
      return new ReplayResult({
        id: ExchangeId(`test-exchange-${callCount}`),
        request: mockRequest,
        response: {
          statusCode: callCount === 1 ? 200 : 403,
          headers: {},
          body: Buffer.from("ok"),
        },
      });
    };

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:hpp",
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
    expect(finding.evidence.judgmentId).toBe("hpp-differential");
    expect(callCount).toBe(2);
  });

  it("detects HPP via body length difference", async () => {
    const plugin = new HppPlugin({ diffThreshold: 30 });
    await initPlugin(plugin);

    const parameter = makeQueryParameter("id", "1");
    let callCount = 0;
    const mockReplay = async () => {
      callCount++;
      return new ReplayResult({
        id: ExchangeId(`test-exchange-${callCount}`),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from(callCount === 1 ? "short" : "much longer response body with different content"),
        },
      });
    };

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:hpp",
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
  });

  it("detects HPP via duplicate value in response", async () => {
    const plugin = new HppPlugin();
    await initPlugin(plugin);

    const parameter = makeQueryParameter("id", "1");
    let callCount = 0;
    const mockReplay = async () => {
      callCount++;
      return new ReplayResult({
        id: ExchangeId(`test-exchange-${callCount}`),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from(callCount === 1 ? "ok" : "received: hpp_duplicate_value"),
        },
      });
    };

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:hpp",
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
  });

  it("does not report vulnerability on identical responses", async () => {
    const plugin = new HppPlugin();
    await initPlugin(plugin);

    const parameter = makeQueryParameter("id", "1");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from("identical response"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:hpp",
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
  });

  it("respects custom diffThreshold", async () => {
    const plugin = new HppPlugin({ diffThreshold: 1000 });
    await initPlugin(plugin);

    const parameter = makeQueryParameter("id", "1");
    let callCount = 0;
    const mockReplay = async () => {
      callCount++;
      return new ReplayResult({
        id: ExchangeId(`test-exchange-${callCount}`),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          // Same body twice — no diff, no status change, no marker
          body: Buffer.from("identical response both times"),
        },
      });
    };

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:hpp",
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
  });
});
