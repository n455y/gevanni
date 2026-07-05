import { describe, it, expect, vi, beforeEach } from "vitest";
import { OpenApiScenarioType } from "../plugins/scenario/openapi.ts";
import { InMemoryCommandBus } from "./command-bus.ts";
import { InMemoryEventBus } from "./event-bus.ts";
import { RuntimeContext } from "./runtime-context.ts";
import { createLogger } from "./logger.ts";
import { Orchestrator } from "./orchestrator.ts";
import { PluginRegistryImpl, type ReporterPlugin } from "./plugin.ts";
import type { AuditItem } from "./audit-item.ts";
import type {
  Evidence,
  Finding,
  HttpRequest,
  HttpResponse,
  SignatureJob,
  ScanState,
  Scenario,
} from "../types/models.ts";
import {
  SignatureJobStatus,
  ScanStatus,
  BuiltinMutationType,
  ReplayResult,
} from "../types/models.ts";
import type { AuditParameter } from "../types/models.ts";
import {
  ScanId,
  SignatureJobId,
  ExchangeId,
  ScenarioId,

  ErrorMessage,
} from "../types/branded.ts";
import { QueryParameter } from "../plugins/parameter/query/model.ts";
import {
  ReplayCommand,
  ParseRequestCommand,
  CreateAuditItemsCommand,
  RunAuditCommand,
  SaveJobCommand,
  LoadJobsByStatusCommand,
  UpdateJobCommand,
  SaveScanStateCommand,
  LoadScanStateCommand,
  SaveScenarioCommand,
  LoadScenarioCommand,
  CreateProxyCommand,
} from "../commands/index.ts";

// --- Mock data helpers ---

const mockRequest: HttpRequest = {
  method: "GET",
  url: "https://example.com/test?q=hello",
  headers: {},
  body: null,
};

const mockResponse: HttpResponse = {
  statusCode: 200,
  headers: {},
  body: Buffer.from("ok"),
};

const mockTargets: AuditParameter[] = [
  new QueryParameter({ name: "q" }, "hello", [
    BuiltinMutationType.ReplaceValue,
  ]),
];

const mockExchange = {
  id: ExchangeId("ex-0"),
  request: mockRequest,
  response: mockResponse,
};
const mockFinding: Finding = {
  vulnerable: false,
  evidence: {
    judgmentId: "mock-check",
    exchanges: [mockExchange],
    evidenceExchanges: [],
  },
  request: mockRequest,
  response: mockResponse,
};

// --- Mock logger ---

function createMockLogger() {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  };
}

describe("Orchestrator", () => {
  let commandBus: InMemoryCommandBus;
  let eventBus: InMemoryEventBus;
  let logger: ReturnType<typeof createMockLogger>;

  beforeEach(() => {
    commandBus = new InMemoryCommandBus();
    eventBus = new InMemoryEventBus();
    logger = createMockLogger();
    commandBus.register(CreateProxyCommand, async () => ({
      port: 0,
      close: vi.fn(),
    }));
  });

  describe("plan phase", () => {
    it("creates jobs and items for scenarios", async () => {
      commandBus.register(ReplayCommand, async () =>
        new ReplayResult({
          id: ExchangeId("ex-1"),
          request: mockRequest,
          response: mockResponse,
        }),
      );

      commandBus.register(ParseRequestCommand, async () => mockTargets);

      const mockItem: AuditItem = {
        signatureName: "signature:mock-sig",
        groups: [],
        parameter: mockTargets[0],
      };
      commandBus.register(CreateAuditItemsCommand, async () => [mockItem]);

      const savedJobs: SignatureJob[] = [];
      commandBus.register(SaveJobCommand, async (cmd) => {
        savedJobs.push(cmd.job);
      });

      commandBus.register(SaveScanStateCommand, async () => {});

      const events: string[] = [];
      eventBus.subscribe("scan:started", () => {
        events.push("scan:started");
      });
      eventBus.subscribe("plan:jobCreated", () => {
        events.push("plan:jobCreated");
      });

      const ctx = new RuntimeContext({ commandBus, eventBus, logger });
      const orchestrator = new Orchestrator({
        context: ctx,
      });

      const result = await orchestrator.plan([]);

      expect(result.scanId).toBeDefined();
      expect(result.items.size).toBe(0);
      expect(events).toContain("scan:started");
    });

    it("processes provided scenarios and creates jobs", async () => {
      const mockScenario: Scenario = {
        id: ScenarioId("sc-1"),
        name: "Test Scenario",
        type: OpenApiScenarioType,
        source: {
          items: [
            {
              request: { method: "GET", url: { raw: "https://example.com" } },
            },
          ],
        },
        representation: "  Test Scenario\n    GET https://example.com",
        diffStrategy: { type: "exact" },
      };

      commandBus.register(ReplayCommand, async () =>
        new ReplayResult({
          id: ExchangeId("ex-1"),
          request: mockRequest,
          response: mockResponse,
        }),
      );
      commandBus.register(ParseRequestCommand, async () => mockTargets);

      const mockItem: AuditItem = {
        signatureName: "signature:mock-sig",
        groups: [],
        parameter: mockTargets[0],
      };
      commandBus.register(CreateAuditItemsCommand, async () => [mockItem]);

      const savedJobs: SignatureJob[] = [];
      commandBus.register(SaveJobCommand, async (cmd) => {
        savedJobs.push(cmd.job);
      });
      commandBus.register(SaveScenarioCommand, async () => {});
      commandBus.register(SaveScanStateCommand, async () => {});

      const events: string[] = [];
      eventBus.subscribe("plan:jobCreated", () => {
        events.push("plan:jobCreated");
      });

      const ctx = new RuntimeContext({ commandBus, eventBus, logger });
      const orchestrator = new Orchestrator({
        context: ctx,
      });

      const result = await orchestrator.plan([mockScenario]);

      expect(savedJobs).toHaveLength(1);
      expect(savedJobs[0].scenarioId).toBe("sc-1");
      expect(savedJobs[0].signatureName).toBe("signature:mock-sig");
      expect(result.items.size).toBe(1);
      expect(events).toContain("plan:jobCreated");
    });

    it("saves scan state with planning status", async () => {
      commandBus.register(ReplayCommand, async () =>
        new ReplayResult({
          id: ExchangeId("ex-1"),
          request: mockRequest,
          response: mockResponse,
        }),
      );
      commandBus.register(ParseRequestCommand, async () => []);
      commandBus.register(CreateAuditItemsCommand, async () => []);
      commandBus.register(SaveJobCommand, async () => {});
      commandBus.register(SaveScanStateCommand, async () => {});

      const ctx = new RuntimeContext({ commandBus, eventBus, logger });
      const orchestrator = new Orchestrator({
        context: ctx,
      });

      const result = await orchestrator.plan([]);
      expect(result.scanId).toBeDefined();
      expect(typeof (result.scanId as string)).toBe("string");
    });
  });

  describe("scan phase", () => {
    it("runs jobs and updates their status", async () => {
      const scanId = ScanId("test-scan-id");
      const mockJob: SignatureJob = {
        id: SignatureJobId("job-1"),
        scanId: ScanId("test-scan-id"),
        scenarioId: ScenarioId("scenario-1"),
        signatureName: "signature:mock-sig",
        groups: [],
        parameter: mockTargets[0],
        status: SignatureJobStatus.Pending,
        finding: null,
        error: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const items = new Map<string, AuditItem>();
      items.set("job-1", {
        signatureName: "signature:mock-sig",
        groups: [],
        parameter: mockTargets[0],
      });

      const updateCalls: Partial<SignatureJob>[] = [];
      const events: string[] = [];

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadJobsByStatusCommand, async (cmd) => {
        if (cmd.statusFilter.includes(SignatureJobStatus.Pending))
          return [mockJob];
        return [];
      });
      commandBus.register(UpdateJobCommand, async (_cmd) => {
        updateCalls.push(_cmd.updates);
      });
      commandBus.register(LoadScenarioCommand, async () => ({
        id: mockJob.scenarioId,
        name: "test",
        type: OpenApiScenarioType,
        source: {
          items: [
            { request: { method: "GET", url: { raw: "https://example.com" } } },
          ],
        },
        representation: "  test\n    GET https://example.com",
        diffStrategy: { type: "exact" },
      }));
      commandBus.register(ReplayCommand, async () =>
        new ReplayResult({
          id: ExchangeId("ex-1"),
          request: mockRequest,
          response: mockResponse,
        }),
      );
      commandBus.register(RunAuditCommand, "signature:mock-sig", async () => ({
        status: "completed",
        finding: mockFinding,
      }));

      eventBus.subscribe("scan:jobStarted", () => {
        events.push("started");
      });
      eventBus.subscribe("scan:jobCompleted", () => {
        events.push("completed");
      });

      const ctx = new RuntimeContext({ commandBus, eventBus, logger });
      const orchestrator = new Orchestrator({
        context: ctx,
      });

      await orchestrator.scan(scanId, items, 2);

      expect(updateCalls.length).toBeGreaterThanOrEqual(2);
      expect(updateCalls[0].status).toBe(SignatureJobStatus.Running);
      expect(updateCalls[1].status).toBe(SignatureJobStatus.Completed);
      expect(events).toContain("started");
      expect(events).toContain("completed");
    });

    it("handles job errors gracefully", async () => {
      const scanId = ScanId("test-scan-id");
      const mockJob: SignatureJob = {
        id: SignatureJobId("job-err"),
        scanId: ScanId("test-scan-id"),
        scenarioId: ScenarioId("scenario-1"),
        signatureName: "signature:failing-sig",
        groups: [],
        parameter: mockTargets[0],
        status: SignatureJobStatus.Pending,
        finding: null,
        error: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const items = new Map<string, AuditItem>();
      items.set("job-err", {
        signatureName: "signature:failing-sig",
        groups: [],
        parameter: mockTargets[0],
      });

      const updateCalls: Partial<SignatureJob>[] = [];
      const events: string[] = [];

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadJobsByStatusCommand, async (cmd) => {
        if (cmd.statusFilter.includes(SignatureJobStatus.Pending))
          return [mockJob];
        return [];
      });
      commandBus.register(UpdateJobCommand, async (_cmd) => {
        updateCalls.push(_cmd.updates);
      });
      commandBus.register(LoadScenarioCommand, async () => ({
        id: mockJob.scenarioId,
        name: "test",
        type: OpenApiScenarioType,
        source: {
          items: [
            { request: { method: "GET", url: { raw: "https://example.com" } } },
          ],
        },
        representation: "  test\n    GET https://example.com",
        diffStrategy: { type: "exact" },
      }));
      commandBus.register(ReplayCommand, async () =>
        new ReplayResult({
          id: ExchangeId("ex-1"),
          request: mockRequest,
          response: mockResponse,
        }),
      );
      commandBus.register(RunAuditCommand, "signature:failing-sig", async () => {
        return {
          status: "error",
          error: ErrorMessage("Inspection failed"),
        } as const;
      });

      eventBus.subscribe("scan:jobError", () => {
        events.push("error");
      });

      const ctx = new RuntimeContext({ commandBus, eventBus, logger });
      const orchestrator = new Orchestrator({
        context: ctx,
      });

      await orchestrator.scan(scanId, items, 2);

      expect(events).toContain("error");
      expect(updateCalls.length).toBeGreaterThanOrEqual(2);
      expect(updateCalls[0].status).toBe(SignatureJobStatus.Running);
      expect(updateCalls[1].status).toBe(SignatureJobStatus.Error);
    });

    it("handles empty job list", async () => {
      const scanId = ScanId("test-scan-id");
      const items = new Map<string, AuditItem>();

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadJobsByStatusCommand, async () => []);

      const ctx = new RuntimeContext({ commandBus, eventBus, logger });
      const orchestrator = new Orchestrator({
        context: ctx,
      });

      await orchestrator.scan(scanId, items, 2);

      expect(logger.info).toHaveBeenCalledWith("No pending jobs to scan");
    });
  });

  describe("report()", () => {
    it("calls generate() on specified reporters with options", async () => {
      const scanId = ScanId("test-scan");
      const mockScanState: ScanState = {
        id: scanId,
        status: ScanStatus.Completed,
        startedAt: new Date("2024-01-01T00:00:00.000Z"),
        updatedAt: new Date("2024-01-01T00:01:00.000Z"),
      };

      commandBus.register(LoadScanStateCommand, async () => mockScanState);
      commandBus.register(LoadJobsByStatusCommand, async () => []);

      const generateCalls: { scanState: ScanState; jobs: SignatureJob[]; options?: string }[] =
        [];
      const mockReporter: ReporterPlugin = {
        name: "reporter:test",
        async init() {},
        async generate(scanState, jobs, options) {
          generateCalls.push({ scanState, jobs, options });
        },
      };

      const registry = new PluginRegistryImpl();
      registry.register(mockReporter);

      const ctx = new RuntimeContext({
        commandBus,
        eventBus,
        logger,
        pluginRegistry: registry,
      });
      const orchestrator = new Orchestrator({ context: ctx });

      await orchestrator.report(scanId, [
        { name: "test", options: "custom-opt" },
      ]);

      expect(generateCalls).toHaveLength(1);
      expect(generateCalls[0].scanState).toBe(mockScanState);
      expect(generateCalls[0].options).toBe("custom-opt");
    });

    it("defaults to console reporter when no reporters specified", async () => {
      const scanId = ScanId("test-scan");
      const mockScanState: ScanState = {
        id: scanId,
        status: ScanStatus.Completed,
        startedAt: new Date("2024-01-01T00:00:00.000Z"),
        updatedAt: new Date("2024-01-01T00:01:00.000Z"),
      };

      commandBus.register(LoadScanStateCommand, async () => mockScanState);
      commandBus.register(LoadJobsByStatusCommand, async () => []);

      let consoleGenerateCalled = false;
      const consoleReporter: ReporterPlugin = {
        name: "reporter:console",
        async init() {},
        async generate() {
          consoleGenerateCalled = true;
        },
      };

      const registry = new PluginRegistryImpl();
      registry.register(consoleReporter);

      const ctx = new RuntimeContext({
        commandBus,
        eventBus,
        logger,
        pluginRegistry: registry,
      });
      const orchestrator = new Orchestrator({ context: ctx });

      await orchestrator.report(scanId, []);

      expect(consoleGenerateCalled).toBe(true);
    });

    it("throws on invalid reporter name with available list", async () => {
      const scanId = ScanId("test-scan");
      const mockScanState: ScanState = {
        id: scanId,
        status: ScanStatus.Completed,
        startedAt: new Date("2024-01-01T00:00:00.000Z"),
        updatedAt: new Date("2024-01-01T00:01:00.000Z"),
      };

      commandBus.register(LoadScanStateCommand, async () => mockScanState);
      commandBus.register(LoadJobsByStatusCommand, async () => []);

      const consoleReporter: ReporterPlugin = {
        name: "reporter:console",
        async init() {},
        async generate() {},
      };

      const registry = new PluginRegistryImpl();
      registry.register(consoleReporter);

      const ctx = new RuntimeContext({
        commandBus,
        eventBus,
        logger,
        pluginRegistry: registry,
      });
      const orchestrator = new Orchestrator({ context: ctx });

      await expect(
        orchestrator.report(scanId, [{ name: "nonexistent" }]),
      ).rejects.toThrow("Invalid reporter(s): nonexistent");
    });

    it("throws when reporter does not implement generate()", async () => {
      const scanId = ScanId("test-scan");
      const mockScanState: ScanState = {
        id: scanId,
        status: ScanStatus.Completed,
        startedAt: new Date("2024-01-01T00:00:00.000Z"),
        updatedAt: new Date("2024-01-01T00:01:00.000Z"),
      };

      commandBus.register(LoadScanStateCommand, async () => mockScanState);
      commandBus.register(LoadJobsByStatusCommand, async () => []);

      const registry = new PluginRegistryImpl();
      // Reporter without generate() method
      registry.register({
        name: "reporter:bad",
        async init() {},
      });

      const ctx = new RuntimeContext({
        commandBus,
        eventBus,
        logger,
        pluginRegistry: registry,
      });
      const orchestrator = new Orchestrator({ context: ctx });

      await expect(
        orchestrator.report(scanId, [{ name: "bad" }]),
      ).rejects.toThrow("does not implement generate() method");
    });
  });

  describe("scan phase shouldSkip-based skipping", () => {
    const vulnerableFinding: Finding = {
      vulnerable: true,
      evidence: {
        judgmentId: "test",
        exchanges: [mockExchange],
        evidenceExchanges: [mockExchange],
      },
      request: mockRequest,
      response: mockResponse,
    };

    it("completes both jobs by default when shouldSkip returns false", async () => {
      const scanId = ScanId("test-scan-id");
      const scenarioId = ScenarioId("scenario-1");
      const param = mockTargets[0];

      const job1: SignatureJob = {
        id: SignatureJobId("job-1"),
        scanId,
        scenarioId,
        signatureName: "signature:sqli-error",
        groups: [],
        parameter: param,
        status: SignatureJobStatus.Pending,
        finding: null,
        error: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const job2: SignatureJob = {
        id: SignatureJobId("job-2"),
        scanId,
        scenarioId,
        signatureName: "signature:sqli-boolean",
        groups: [],
        parameter: param,
        status: SignatureJobStatus.Pending,
        finding: null,
        error: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const items = new Map<string, AuditItem>();
      items.set("job-1", {
        signatureName: "signature:sqli-error",
        groups: [],
        parameter: param,
      });
      items.set("job-2", {
        signatureName: "signature:sqli-boolean",
        groups: [],
        parameter: param,
      });

      const updateCalls: { jobId: string; updates: Partial<SignatureJob> }[] =
        [];

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadJobsByStatusCommand, async (cmd) => {
        if (cmd.statusFilter.includes(SignatureJobStatus.Pending))
          return [job1, job2];
        return [];
      });
      commandBus.register(UpdateJobCommand, async (cmd) => {
        updateCalls.push({ jobId: cmd.id, updates: cmd.updates });
      });
      commandBus.register(LoadScenarioCommand, async () => ({
        id: scenarioId,
        name: "test",
        type: OpenApiScenarioType,
        source: {
          items: [
            { request: { method: "GET", url: { raw: "https://example.com" } } },
          ],
        },
        representation: "  test\n    GET https://example.com",
        diffStrategy: { type: "exact" },
      }));
      commandBus.register(ReplayCommand, async () => new ReplayResult(mockExchange));
      commandBus.register(RunAuditCommand, "signature:sqli-error", async () => ({
        status: "completed",
        finding: vulnerableFinding,
      }));
      commandBus.register(RunAuditCommand, "signature:sqli-boolean", async () => ({
        status: "completed",
        finding: vulnerableFinding,
      }));

      const ctx = new RuntimeContext({ commandBus, eventBus, logger });
      const orchestrator = new Orchestrator({ context: ctx });
      await orchestrator.scan(scanId, items, 1);

      const job1Updates = updateCalls.filter((c) => c.jobId === "job-1");
      const job2Updates = updateCalls.filter((c) => c.jobId === "job-2");

      expect(
        job1Updates.some(
          (c) => c.updates.status === SignatureJobStatus.Completed,
        ),
      ).toBe(true);
      expect(
        job2Updates.some(
          (c) => c.updates.status === SignatureJobStatus.Completed,
        ),
      ).toBe(true);
    });

    it("does not skip jobs with different parameters", async () => {
      const scanId = ScanId("test-scan-id");
      const scenarioId = ScenarioId("scenario-1");
      const param1 = new QueryParameter({ name: "q" }, "hello", [
        BuiltinMutationType.ReplaceValue,
      ]);
      const param2 = new QueryParameter({ name: "id" }, "123", [
        BuiltinMutationType.ReplaceValue,
      ]);

      const job1: SignatureJob = {
        id: SignatureJobId("job-1"),
        scanId,
        scenarioId,
        signatureName: "signature:sqli-error",
        groups: [],
        parameter: param1,
        status: SignatureJobStatus.Pending,
        finding: null,
        error: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const job2: SignatureJob = {
        id: SignatureJobId("job-2"),
        scanId,
        scenarioId,
        signatureName: "signature:sqli-boolean",
        groups: [],
        parameter: param2,
        status: SignatureJobStatus.Pending,
        finding: null,
        error: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const items = new Map<string, AuditItem>();
      items.set("job-1", {
        signatureName: "signature:sqli-error",
        groups: [],
        parameter: param1,
      });
      items.set("job-2", {
        signatureName: "signature:sqli-boolean",
        groups: [],
        parameter: param2,
      });

      const updateCalls: { jobId: string; updates: Partial<SignatureJob> }[] =
        [];

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadJobsByStatusCommand, async (cmd) => {
        if (cmd.statusFilter.includes(SignatureJobStatus.Pending))
          return [job1, job2];
        return [];
      });
      commandBus.register(UpdateJobCommand, async (cmd) => {
        updateCalls.push({ jobId: cmd.id, updates: cmd.updates });
      });
      commandBus.register(LoadScenarioCommand, async () => ({
        id: scenarioId,
        name: "test",
        type: OpenApiScenarioType,
        source: {
          items: [
            { request: { method: "GET", url: { raw: "https://example.com" } } },
          ],
        },
        representation: "  test\n    GET https://example.com",
        diffStrategy: { type: "exact" },
      }));
      commandBus.register(ReplayCommand, async () => new ReplayResult(mockExchange));
      commandBus.register(RunAuditCommand, "signature:sqli-error", async () => ({
        status: "completed",
        finding: vulnerableFinding,
      }));
      commandBus.register(RunAuditCommand, "signature:sqli-boolean", async () => ({
        status: "completed",
        finding: vulnerableFinding,
      }));

      const ctx = new RuntimeContext({ commandBus, eventBus, logger });
      const orchestrator = new Orchestrator({ context: ctx });
      await orchestrator.scan(scanId, items, 1);

      const job1Updates = updateCalls.filter((c) => c.jobId === "job-1");
      const job2Updates = updateCalls.filter((c) => c.jobId === "job-2");

      expect(
        job1Updates.some(
          (c) => c.updates.status === SignatureJobStatus.Completed,
        ),
      ).toBe(true);
      expect(
        job2Updates.some(
          (c) => c.updates.status === SignatureJobStatus.Completed,
        ),
      ).toBe(true);
    });

    it("completes all jobs when shouldSkip returns false", async () => {
      const scanId = ScanId("test-scan-id");
      const scenarioId = ScenarioId("scenario-1");

      const job1: SignatureJob = {
        id: SignatureJobId("job-1"),
        scanId,
        scenarioId,
        signatureName: "signature:sqli-error",
        groups: [],
        parameter: mockTargets[0],
        status: SignatureJobStatus.Pending,
        finding: null,
        error: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const job2: SignatureJob = {
        id: SignatureJobId("job-2"),
        scanId,
        scenarioId,
        signatureName: "signature:reflected-xss",
        groups: [],
        parameter: mockTargets[0],
        status: SignatureJobStatus.Pending,
        finding: null,
        error: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const items = new Map<string, AuditItem>();
      items.set("job-1", {
        signatureName: "signature:sqli-error",
        groups: [],
        parameter: mockTargets[0],
      });
      items.set("job-2", {
        signatureName: "signature:reflected-xss",
        groups: [],
        parameter: mockTargets[0],
      });

      const updateCalls: { jobId: string; updates: Partial<SignatureJob> }[] =
        [];

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadJobsByStatusCommand, async (cmd) => {
        if (cmd.statusFilter.includes(SignatureJobStatus.Pending))
          return [job1, job2];
        return [];
      });
      commandBus.register(UpdateJobCommand, async (cmd) => {
        updateCalls.push({ jobId: cmd.id, updates: cmd.updates });
      });
      commandBus.register(LoadScenarioCommand, async () => ({
        id: scenarioId,
        name: "test",
        type: OpenApiScenarioType,
        source: {
          items: [
            { request: { method: "GET", url: { raw: "https://example.com" } } },
          ],
        },
        representation: "  test\n    GET https://example.com",
        diffStrategy: { type: "exact" },
      }));
      commandBus.register(ReplayCommand, async () => new ReplayResult(mockExchange));
      commandBus.register(RunAuditCommand, "signature:sqli-error", async () => ({
        status: "completed",
        finding: vulnerableFinding,
      }));
      commandBus.register(RunAuditCommand, "signature:reflected-xss", async () => ({
        status: "completed",
        finding: vulnerableFinding,
      }));

      const ctx = new RuntimeContext({ commandBus, eventBus, logger });
      const orchestrator = new Orchestrator({ context: ctx });
      await orchestrator.scan(scanId, items, 1);

      const job1Updates = updateCalls.filter((c) => c.jobId === "job-1");
      const job2Updates = updateCalls.filter((c) => c.jobId === "job-2");

      expect(
        job1Updates.some(
          (c) => c.updates.status === SignatureJobStatus.Completed,
        ),
      ).toBe(true);
      expect(
        job2Updates.some(
          (c) => c.updates.status === SignatureJobStatus.Completed,
        ),
      ).toBe(true);
    });
  });
});
