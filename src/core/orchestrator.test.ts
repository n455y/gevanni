import { describe, it, expect, vi, beforeEach } from "vitest";
import { PostmanScenarioType } from "../plugins/scenario/postman.ts";
import { InMemoryCommandBus } from "./command-bus.ts";
import { InMemoryEventBus } from "./event-bus.ts";
import { createLogger } from "./logger.ts";
import { Orchestrator } from "./orchestrator.ts";
import type { AuditItem } from "./audit-item.ts";
import type {
  Evidence,
  Finding,
  HttpRequest,
  HttpResponse,
  Job,
  ScanState,
  Scenario,
} from "../types/models.ts";
import type { AuditParameter } from "../types/models.ts";
import {
  BuiltinMutationType,
  ScanId,
  JobId,
  ExchangeId,
  ScenarioId,
  JobStatus,
  ScanStatus,
} from "../types/branded.ts";
import { QueryParameter } from "../plugins/parameter/query.ts";
import {
  ReplayCommand,
  ParseRequestCommand,
  CreateAuditItemsCommand,
  RunAuditCommand,
  SaveJobCommand,
  LoadPendingJobsCommand,
  UpdateJobCommand,
  SaveScanStateCommand,
  LoadScanStateCommand,
  LoadJobsByScanIdCommand,
  GenerateReportCommand,
  SaveScenarioCommand,
  LoadScenarioCommand,
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
  });

  describe("plan phase", () => {
    it("creates jobs and items for scenarios", async () => {
      commandBus.register(ReplayCommand, async () => [
        {
          id: ExchangeId("ex-1"),
          request: mockRequest,
          response: mockResponse,
        },
      ]);

      commandBus.register(ParseRequestCommand, async () => mockTargets);

      const mockItem: AuditItem = {
        signatureName: "mock-sig",
        parameter: mockTargets[0],
      };
      commandBus.register(CreateAuditItemsCommand, async () => [mockItem]);

      const savedJobs: Job[] = [];
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

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
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
        type: PostmanScenarioType,
        source: {
          items: [
            {
              request: { method: "GET", url: { raw: "https://example.com" } },
            },
          ],
        },
      };

      commandBus.register(ReplayCommand, async () => [
        {
          id: ExchangeId("ex-1"),
          request: mockRequest,
          response: mockResponse,
        },
      ]);
      commandBus.register(ParseRequestCommand, async () => mockTargets);

      const mockItem: AuditItem = {
        signatureName: "mock-sig",
        parameter: mockTargets[0],
      };
      commandBus.register(CreateAuditItemsCommand, async () => [mockItem]);

      const savedJobs: Job[] = [];
      commandBus.register(SaveJobCommand, async (cmd) => {
        savedJobs.push(cmd.job);
      });
      commandBus.register(SaveScenarioCommand, async () => {});
      commandBus.register(SaveScanStateCommand, async () => {});

      const events: string[] = [];
      eventBus.subscribe("plan:jobCreated", () => {
        events.push("plan:jobCreated");
      });

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      const result = await orchestrator.plan([mockScenario]);

      expect(savedJobs).toHaveLength(1);
      expect(savedJobs[0].scenarioId).toBe("sc-1");
      expect(savedJobs[0].signatureName).toBe("mock-sig");
      expect(result.items.size).toBe(1);
      expect(events).toContain("plan:jobCreated");
    });

    it("saves scan state with planning status", async () => {
      commandBus.register(ReplayCommand, async () => [
        {
          id: ExchangeId("ex-1"),
          request: mockRequest,
          response: mockResponse,
        },
      ]);
      commandBus.register(ParseRequestCommand, async () => []);
      commandBus.register(CreateAuditItemsCommand, async () => []);
      commandBus.register(SaveJobCommand, async () => {});
      commandBus.register(SaveScanStateCommand, async () => {});

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      const result = await orchestrator.plan([]);
      expect(result.scanId).toBeDefined();
      expect(typeof (result.scanId as string)).toBe("string");
    });
  });

  describe("scan phase", () => {
    it("runs jobs and updates their status", async () => {
      const scanId = ScanId("test-scan-id");
      const mockJob: Job = {
        id: JobId("job-1"),
        scanId: ScanId("test-scan-id"),
        scenarioId: ScenarioId("scenario-1"),
        signatureName: "mock-sig",
        parameter: mockTargets[0],
        status: JobStatus.Pending,
        finding: null,
        error: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const items = new Map<string, AuditItem>();
      items.set("job-1", {
        signatureName: "mock-sig",
        parameter: mockTargets[0],
      });

      const updateCalls: Partial<Job>[] = [];
      const events: string[] = [];

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadPendingJobsCommand, async () => [mockJob]);
      commandBus.register(UpdateJobCommand, async (_cmd) => {
        updateCalls.push(_cmd.updates);
      });
      commandBus.register(LoadScenarioCommand, async () => ({
        id: mockJob.scenarioId,
        name: "test",
        type: PostmanScenarioType,
        source: {
          items: [
            { request: { method: "GET", url: { raw: "https://example.com" } } },
          ],
        },
      }));
      commandBus.register(ReplayCommand, async () => [
        {
          id: ExchangeId("ex-1"),
          request: mockRequest,
          response: mockResponse,
        },
      ]);
      commandBus.register(RunAuditCommand, "mock-sig", async () => mockFinding);

      eventBus.subscribe("scan:jobStarted", () => {
        events.push("started");
      });
      eventBus.subscribe("scan:jobCompleted", () => {
        events.push("completed");
      });

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      await orchestrator.scan(scanId, items, 2);

      expect(updateCalls.length).toBeGreaterThanOrEqual(2);
      expect(updateCalls[0].status).toBe(JobStatus.Running);
      expect(updateCalls[1].status).toBe(JobStatus.Completed);
      expect(events).toContain("started");
      expect(events).toContain("completed");
    });

    it("handles job errors gracefully", async () => {
      const scanId = ScanId("test-scan-id");
      const mockJob: Job = {
        id: JobId("job-err"),
        scanId: ScanId("test-scan-id"),
        scenarioId: ScenarioId("scenario-1"),
        signatureName: "failing-sig",
        parameter: mockTargets[0],
        status: JobStatus.Pending,
        finding: null,
        error: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const items = new Map<string, AuditItem>();
      items.set("job-err", {
        signatureName: "failing-sig",
        parameter: mockTargets[0],
      });

      const updateCalls: Partial<Job>[] = [];
      const events: string[] = [];

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadPendingJobsCommand, async () => [mockJob]);
      commandBus.register(UpdateJobCommand, async (_cmd) => {
        updateCalls.push(_cmd.updates);
      });
      commandBus.register(LoadScenarioCommand, async () => ({
        id: mockJob.scenarioId,
        name: "test",
        type: PostmanScenarioType,
        source: {
          items: [
            { request: { method: "GET", url: { raw: "https://example.com" } } },
          ],
        },
      }));
      commandBus.register(ReplayCommand, async () => [
        {
          id: ExchangeId("ex-1"),
          request: mockRequest,
          response: mockResponse,
        },
      ]);
      commandBus.register(RunAuditCommand, "failing-sig", async () => {
        throw new Error("Inspection failed");
      });

      eventBus.subscribe("scan:jobError", () => {
        events.push("error");
      });

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      await orchestrator.scan(scanId, items, 2);

      expect(events).toContain("error");
      expect(updateCalls.length).toBeGreaterThanOrEqual(2);
      expect(updateCalls[0].status).toBe(JobStatus.Running);
      expect(updateCalls[1].status).toBe(JobStatus.Error);
    });

    it("handles empty job list", async () => {
      const scanId = ScanId("test-scan-id");
      const items = new Map<string, AuditItem>();

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadPendingJobsCommand, async () => []);

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      await orchestrator.scan(scanId, items, 2);

      expect(logger.info).toHaveBeenCalledWith("No pending jobs to scan");
    });
  });

  describe("report phase", () => {
    it("broadcasts GenerateReportCommand with scan state and jobs", async () => {
      const scanId = ScanId("report-scan-id");
      const mockScanState: ScanState = {
        id: scanId,
        status: ScanStatus.Completed,
        startedAt: new Date("2024-01-01T00:00:00.000Z"),
        updatedAt: new Date("2024-01-01T00:01:00.000Z"),
      };

      const mockJobs: Job[] = [
        {
          id: JobId("job-1"),
          scanId: ScanId("report-scan-id"),
          scenarioId: ScenarioId("sc-1"),
          signatureName: "reflected-xss",
          parameter: mockTargets[0],
          status: JobStatus.Completed,
          finding: mockFinding,
          error: null,
          createdAt: new Date("2024-01-01T00:00:00.000Z"),
          updatedAt: new Date("2024-01-01T00:00:01.000Z"),
        },
      ];

      commandBus.register(LoadScanStateCommand, async () => mockScanState);
      commandBus.register(LoadJobsByScanIdCommand, async () => mockJobs);

      let reportPayload: { scanState: ScanState; jobs: Job[] } | null = null;
      commandBus.register(GenerateReportCommand, async (cmd) => {
        reportPayload = cmd.payload;
      });

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      await orchestrator.report(scanId);

      expect(reportPayload).toBeDefined();
      expect(reportPayload!.scanState).toBe(mockScanState);
      expect(reportPayload!.jobs).toBe(mockJobs);
    });

    it("warns when scan state not found", async () => {
      const scanId = ScanId("missing-scan");

      commandBus.register(LoadScanStateCommand, async () => null);

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      await orchestrator.report(scanId);

      expect(logger.warn).toHaveBeenCalledWith(
        `No scan state found for ${scanId}`,
      );
    });
  });
});
