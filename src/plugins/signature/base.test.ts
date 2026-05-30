import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { SignaturePluginBase } from "./base.ts";
import { SqliBooleanPlugin } from "./sqli-boolean.ts";
import { SqliErrorPlugin } from "./sqli-error.ts";
import { ReflectedXssPlugin } from "./reflected-xss.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type { AuditParameter, Finding, SignatureJob } from "../../types/models.ts";
import { ReplayResult, BuiltinMutationType } from "../../types/models.ts";
import { QueryParameter } from "../parameter/query.ts";
import { ExchangeId, ScenarioId, SignatureId, SignatureGroupId } from "../../types/branded.ts";

const noopLogger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

function makeQueryParameter(name: string, value: string): AuditParameter {
  return new QueryParameter({ name }, value, [
    BuiltinMutationType.AppendValue,
  ]);
}

function makeCompletedJob(
  signatureName: string,
  vulnerable: boolean,
  categories: SignatureGroupId[] = [],
): SignatureJob {
  return {
    id: "job-id" as any,
    scanId: "scan-id" as any,
    scenarioId: ScenarioId("test-scenario"),
    signatureName: SignatureId(signatureName),
    categories,
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

  beforeEach(() => {
    commandBus = new InMemoryCommandBus();
  });

  it("skips when same category already found vulnerability", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    // Register sqli-boolean too so its category is in the registry
    const booleanPlugin = new SqliBooleanPlugin();
    await booleanPlugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const results = await commandBus.dispatch(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-error"),
        scenarioId: ScenarioId("test-scenario"),
        parameter: makeQueryParameter("id", "1"),
        replay: async () => new ReplayResult({
          id: ExchangeId("test"),
          request: { method: "GET", url: "", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        }),
        completedJobs: [makeCompletedJob("sqli-boolean", true, [SignatureGroupId("sqli")])],
      }),
    );

    expect(results.status).toBe("skipped");
  });

  it("does not skip when same category found no vulnerability", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const booleanPlugin = new SqliBooleanPlugin();
    await booleanPlugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const results = await commandBus.dispatch(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-error"),
        scenarioId: ScenarioId("test-scenario"),
        parameter: makeQueryParameter("id", "1"),
        replay: async () => new ReplayResult({
          id: ExchangeId("test"),
          request: { method: "GET", url: "", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        }),
        completedJobs: [makeCompletedJob("sqli-boolean", false, [SignatureGroupId("sqli")])],
      }),
    );

    expect(results.status).toBe("completed");
  });

  it("does not skip when different category found vulnerability", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const xssPlugin = new ReflectedXssPlugin();
    await xssPlugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const results = await commandBus.dispatch(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-error"),
        scenarioId: ScenarioId("test-scenario"),
        parameter: makeQueryParameter("id", "1"),
        replay: async () => new ReplayResult({
          id: ExchangeId("test"),
          request: { method: "GET", url: "", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        }),
        completedJobs: [makeCompletedJob("reflected-xss", true)],
      }),
    );

    expect(results.status).toBe("completed");
  });

  it("does not skip when no completed jobs", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const results = await commandBus.dispatch(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-error"),
        scenarioId: ScenarioId("test-scenario"),
        parameter: makeQueryParameter("id", "1"),
        replay: async () => new ReplayResult({
          id: ExchangeId("test"),
          request: { method: "GET", url: "", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        }),
        completedJobs: [],
      }),
    );

    expect(results.status).toBe("completed");
  });

  describe("multiple categories", () => {
    class MultiCategoryPlugin extends SignaturePluginBase {
      readonly name = SignatureId("multi-cat-test");
      protected override get categories() {
        return [SignatureGroupId("cat-a"), SignatureGroupId("cat-b")];
      }
      protected async runAudit() {
        return {
          vulnerable: false,
          evidence: { judgmentId: "test", exchanges: [], evidenceExchanges: [] },
          request: { method: "GET", url: "", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        };
      }
    }

    class SingleCategoryPlugin extends SignaturePluginBase {
      readonly name = SignatureId("cat-a-member");
      protected override get categories() {
        return [SignatureGroupId("cat-a")];
      }
      protected async runAudit() {
        return {
          vulnerable: false,
          evidence: { judgmentId: "test", exchanges: [], evidenceExchanges: [] },
          request: { method: "GET", url: "", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        };
      }
    }

    it("skips when all categories have detected vulnerability", async () => {
      const plugin = new MultiCategoryPlugin();
      await plugin.init({
        commandBus,
        eventBus: new InMemoryEventBus(),
        logger: noopLogger,
      });

      // Register a plugin in cat-a
      const catAPlugin = new SingleCategoryPlugin();
      await catAPlugin.init({
        commandBus,
        eventBus: new InMemoryEventBus(),
        logger: noopLogger,
      });

      const results = await commandBus.dispatch(
        new RunAuditCommand({
          signatureName: SignatureId("multi-cat-test"),
        scenarioId: ScenarioId("test-scenario"),
          parameter: makeQueryParameter("id", "1"),
          replay: async () => new ReplayResult({
            id: ExchangeId("test"),
            request: { method: "GET", url: "", headers: {}, body: null },
            response: { statusCode: 200, headers: {}, body: null },
          }),
          completedJobs: [
            makeCompletedJob("cat-a-member", true, [SignatureGroupId("cat-a")]),
            makeCompletedJob("multi-cat-test", true, [SignatureGroupId("cat-a"), SignatureGroupId("cat-b")]),
          ],
        }),
      );

      expect(results.status).toBe("skipped");
    });

    it("does not skip when only some categories have detected vulnerability", async () => {
      const plugin = new MultiCategoryPlugin();
      await plugin.init({
        commandBus,
        eventBus: new InMemoryEventBus(),
        logger: noopLogger,
      });

      const catAPlugin = new SingleCategoryPlugin();
      await catAPlugin.init({
        commandBus,
        eventBus: new InMemoryEventBus(),
        logger: noopLogger,
      });

      const results = await commandBus.dispatch(
        new RunAuditCommand({
          signatureName: SignatureId("multi-cat-test"),
        scenarioId: ScenarioId("test-scenario"),
          parameter: makeQueryParameter("id", "1"),
          replay: async () => new ReplayResult({
            id: ExchangeId("test"),
            request: { method: "GET", url: "", headers: {}, body: null },
            response: { statusCode: 200, headers: {}, body: null },
          }),
          completedJobs: [
            makeCompletedJob("cat-a-member", true, [SignatureGroupId("cat-a")]),
            // cat-b has no vulnerable detection
          ],
        }),
      );

      expect(results.status).toBe("completed");
    });
  });
});
