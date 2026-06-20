import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { PluginRegistryImpl } from "../../core/plugin.ts";
import { SignaturePluginBase } from "./base.ts";
import { SqliBooleanPlugin } from "./sqli-boolean.ts";
import { SqliErrorPlugin } from "./sqli-error.ts";
import { ReflectedXssPlugin } from "./reflected-xss.ts";
import { ExactDiffPlugin } from "../diff/exact.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type {
  AuditParameter,
  Finding,
  Scenario,
  SignatureJob,
} from "../../types/models.ts";
import { ReplayResult, BuiltinMutationType } from "../../types/models.ts";
import { QueryParameter } from "../parameter/query.ts";
import {
  ExchangeId,
  ScenarioId,
  ScenarioType,
  SignatureGroupId,
} from "../../types/branded.ts";

function makeScenario(overrides: Partial<Scenario> = {}): Scenario {
  return {
    id: ScenarioId("test-scenario"),
    name: "Test Scenario",
    type: ScenarioType("test"),
    source: null,
    representation: "Test Scenario",
    diffStrategy: "exact",
    ...overrides,
  };
}

const noopLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

function makeQueryParameter(name: string, value: string): AuditParameter {
  return new QueryParameter({ name }, value, [BuiltinMutationType.AppendValue]);
}

function makeCompletedJob(
  signatureName: `signature:${string}`,
  vulnerable: boolean,
  groups: SignatureGroupId[] = [],
): SignatureJob {
  return {
    id: "job-id" as any,
    scanId: "scan-id" as any,
    scenarioId: ScenarioId("test-scenario"),
    signatureName,
    groups,
    parameter: makeQueryParameter("id", "1"),
    status: "completed" as any,
    finding: {
      vulnerable,
      evidence: { judgmentId: "test", exchanges: [], evidenceExchanges: [] },
      request: { method: "GET", url: "", headers: {}, body: null },
      response: { statusCode: 200, headers: {}, body: null },
    },
    error: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

describe("SignaturePluginBase isAlreadyChecked", () => {
  let commandBus: InMemoryCommandBus;
  let registry: PluginRegistryImpl;

  beforeEach(() => {
    commandBus = new InMemoryCommandBus();
    registry = new PluginRegistryImpl();
    registry.register(new ExactDiffPlugin());
  });

  function makeContext() {
    return {
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
      pluginRegistry: registry,
    };
  }

  it("skips when same group already found vulnerability", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init(makeContext());

    // Register sqli-boolean too so its group is in the registry
    const booleanPlugin = new SqliBooleanPlugin();
    await booleanPlugin.init(makeContext());

    const results = await commandBus.dispatch(
      new RunAuditCommand({
        signatureName: "signature:sqli-error",
        scenario: makeScenario(),
        parameter: makeQueryParameter("id", "1"),
        replay: async () =>
          new ReplayResult({
            id: ExchangeId("test"),
            request: { method: "GET", url: "", headers: {}, body: null },
            response: { statusCode: 200, headers: {}, body: null },
          }),
        completedJobs: [
          makeCompletedJob("signature:sqli-boolean", true, [SignatureGroupId("sqli")]),
        ],
      }),
    );

    expect(results.status).toBe("skipped");
  });

  it("does not skip when same group found no vulnerability", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init(makeContext());

    const booleanPlugin = new SqliBooleanPlugin();
    await booleanPlugin.init(makeContext());

    const results = await commandBus.dispatch(
      new RunAuditCommand({
        signatureName: "signature:sqli-error",
        scenario: makeScenario(),
        parameter: makeQueryParameter("id", "1"),
        replay: async () =>
          new ReplayResult({
            id: ExchangeId("test"),
            request: { method: "GET", url: "", headers: {}, body: null },
            response: { statusCode: 200, headers: {}, body: null },
          }),
        completedJobs: [
          makeCompletedJob("signature:sqli-boolean", false, [SignatureGroupId("sqli")]),
        ],
      }),
    );

    expect(results.status).toBe("completed");
  });

  it("does not skip when different group found vulnerability", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init(makeContext());

    const xssPlugin = new ReflectedXssPlugin();
    await xssPlugin.init(makeContext());

    const results = await commandBus.dispatch(
      new RunAuditCommand({
        signatureName: "signature:sqli-error",
        scenario: makeScenario(),
        parameter: makeQueryParameter("id", "1"),
        replay: async () =>
          new ReplayResult({
            id: ExchangeId("test"),
            request: { method: "GET", url: "", headers: {}, body: null },
            response: { statusCode: 200, headers: {}, body: null },
          }),
        completedJobs: [makeCompletedJob("signature:reflected-xss", true)],
      }),
    );

    expect(results.status).toBe("completed");
  });

  it("does not skip when no completed jobs", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init(makeContext());

    const results = await commandBus.dispatch(
      new RunAuditCommand({
        signatureName: "signature:sqli-error",
        scenario: makeScenario(),
        parameter: makeQueryParameter("id", "1"),
        replay: async () =>
          new ReplayResult({
            id: ExchangeId("test"),
            request: { method: "GET", url: "", headers: {}, body: null },
            response: { statusCode: 200, headers: {}, body: null },
          }),
        completedJobs: [],
      }),
    );

    expect(results.status).toBe("completed");
  });

  describe("multiple groups", () => {
    class MultiGroupPlugin extends SignaturePluginBase {
      readonly name = "signature:multi-cat-test";
      protected readonly groups = [
        SignatureGroupId("cat-a"),
        SignatureGroupId("cat-b"),
      ];
      protected async runAudit() {
        return {
          vulnerable: false,
          evidence: {
            judgmentId: "test",
            exchanges: [],
            evidenceExchanges: [],
          },
          request: { method: "GET", url: "", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        };
      }
    }

    class SingleGroupPlugin extends SignaturePluginBase {
      readonly name = "signature:cat-a-member";
      protected readonly groups = [SignatureGroupId("cat-a")];
      protected async runAudit() {
        return {
          vulnerable: false,
          evidence: {
            judgmentId: "test",
            exchanges: [],
            evidenceExchanges: [],
          },
          request: { method: "GET", url: "", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        };
      }
    }

    it("skips when all groups have detected vulnerability", async () => {
      const plugin = new MultiGroupPlugin();
      await plugin.init(makeContext());

      // Register a plugin in cat-a
      const catAPlugin = new SingleGroupPlugin();
      await catAPlugin.init(makeContext());

      const results = await commandBus.dispatch(
        new RunAuditCommand({
          signatureName: "signature:multi-cat-test",
          scenario: makeScenario(),
          parameter: makeQueryParameter("id", "1"),
          replay: async () =>
            new ReplayResult({
              id: ExchangeId("test"),
              request: { method: "GET", url: "", headers: {}, body: null },
              response: { statusCode: 200, headers: {}, body: null },
            }),
          completedJobs: [
            makeCompletedJob("signature:cat-a-member", true, [SignatureGroupId("cat-a")]),
            makeCompletedJob("signature:multi-cat-test", true, [
              SignatureGroupId("cat-a"),
              SignatureGroupId("cat-b"),
            ]),
          ],
        }),
      );

      expect(results.status).toBe("skipped");
    });

    it("does not skip when only some groups have detected vulnerability", async () => {
      const plugin = new MultiGroupPlugin();
      await plugin.init(makeContext());

      const catAPlugin = new SingleGroupPlugin();
      await catAPlugin.init(makeContext());

      const results = await commandBus.dispatch(
        new RunAuditCommand({
          signatureName: "signature:multi-cat-test",
          scenario: makeScenario(),
          parameter: makeQueryParameter("id", "1"),
          replay: async () =>
            new ReplayResult({
              id: ExchangeId("test"),
              request: { method: "GET", url: "", headers: {}, body: null },
              response: { statusCode: 200, headers: {}, body: null },
            }),
          completedJobs: [
            makeCompletedJob("signature:cat-a-member", true, [SignatureGroupId("cat-a")]),
            // cat-b has no vulnerable detection
          ],
        }),
      );

      expect(results.status).toBe("completed");
    });
  });
});
