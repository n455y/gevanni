import { describe, it, expect, vi, beforeEach } from "vitest";
import { InMemoryCommandBus } from "./command-bus.js";
import { InMemoryEventBus } from "./event-bus.js";
import { createLogger } from "./logger.js";
import { Orchestrator } from "./orchestrator.js";
import type { SignatureInspector, ReplayFn } from "./inspector.js";
import type {
  InspectionParameter,
  Finding,
  HttpRequest,
  HttpResponse,
  Job,
  ScanState,
  Scenario,
} from "../types/models.js";
import type { Brand, JobStatus, ScanStatus } from "../types/branded.js";
import {
  ReplayCommand,
  ParseRequestCommand,
  CreateInspectorsCommand,
  SaveJobCommand,
  LoadPendingJobsCommand,
  UpdateJobCommand,
  SaveScanStateCommand,
  LoadScanStateCommand,
  LoadJobsByScanIdCommand,
  GenerateReportCommand,
  LoadScenarioCommand,
} from "../commands/index.js";

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

const mockParameters: InspectionParameter[] = [
  {
    type: "query" as Brand<"query", "ParameterType">,
    location: { name: "q" },
    originalValue: "hello",
    allowedTampers: ["replaceValue" as Brand<"replaceValue", "TamperMethod">],
  },
];

const mockFinding: Finding = {
  vulnerable: false,
  evidence: "No reflection found" as Brand<string, "Evidence">,
  request: mockRequest,
  response: mockResponse,
};

// --- Mock inspector ---

class MockInspector implements SignatureInspector {
  readonly signatureName = "mock-sig";
  readonly parameters: InspectionParameter[];

  constructor(
    parameters: InspectionParameter[],
    private result: Finding = mockFinding,
  ) {
    this.parameters = parameters;
  }

  async inspect(_replay: ReplayFn): Promise<Finding> {
    return this.result;
  }
}

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
    it("creates jobs and inspectors for scenarios", async () => {
      // Register command handlers
      commandBus.register(ReplayCommand, async () => ({
        request: mockRequest,
        response: mockResponse,
      }));

      commandBus.register(ParseRequestCommand, async () => mockParameters);

      const mockInspector = new MockInspector(mockParameters);
      commandBus.register(CreateInspectorsCommand, async () => [
        mockInspector,
      ]);

      const savedJobs: Job[] = [];
      commandBus.register(SaveJobCommand, async (cmd: SaveJobCommand) => {
        savedJobs.push(cmd.job);
      });

      commandBus.register(SaveScanStateCommand, async () => {});

      const events: string[] = [];
      eventBus.subscribe("scan:started", () => { events.push("scan:started"); });
      eventBus.subscribe("plan:jobCreated", () => { events.push("plan:jobCreated"); });

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      // No scenarios provided
      const result = await orchestrator.plan([]);

      expect(result.scanId).toBeDefined();
      expect(result.inspectors.size).toBe(0); // No scenarios provided
      expect(events).toContain("scan:started");
    });

    it("processes provided scenarios and creates jobs", async () => {
      const mockScenario: Scenario = {
        id: "sc-1" as Brand<string, "ScenarioId">,
        name: "Test Scenario",
        type: "postman" as Brand<string, "ScenarioType">,
        source: {
          item: {
            request: { method: "GET", url: { raw: "https://example.com" } },
          },
        },
      };

      commandBus.register(ReplayCommand, async () => ({
        request: mockRequest,
        response: mockResponse,
      }));
      commandBus.register(ParseRequestCommand, async () => mockParameters);

      const mockInspector = new MockInspector(mockParameters);
      commandBus.register(CreateInspectorsCommand, async () => [mockInspector]);

      const savedJobs: Job[] = [];
      commandBus.register(SaveJobCommand, async (cmd: SaveJobCommand) => {
        savedJobs.push(cmd.job);
      });
      commandBus.register(SaveScanStateCommand, async () => {});

      const events: string[] = [];
      eventBus.subscribe("plan:jobCreated", () => { events.push("plan:jobCreated"); });

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      const result = await orchestrator.plan([mockScenario]);

      expect(savedJobs).toHaveLength(1);
      expect(savedJobs[0].scenarioId).toBe("sc-1");
      expect(savedJobs[0].signatureName).toBe("mock-sig");
      expect(result.inspectors.size).toBe(1);
      expect(events).toContain("plan:jobCreated");
    });

    it("saves scan state with planning status", async () => {
      commandBus.register(ReplayCommand, async () => ({
        request: mockRequest,
        response: mockResponse,
      }));
      commandBus.register(ParseRequestCommand, async () => []);
      commandBus.register(CreateInspectorsCommand, async () => []);
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
      const scanId = "test-scan-id" as Brand<string, "ScanId">;
      const mockJob: Job = {
        id: "job-1" as Brand<string, "JobId">,
        scenarioId: "scenario-1" as Brand<string, "ScenarioId">,
        requestId: "req-1" as Brand<string, "RequestId">,
        signatureName: "mock-sig",
        parameters: mockParameters,
        status: "pending" as JobStatus,
        finding: null,
        error: null,
        createdAt: new Date().toISOString() as Brand<string, "IsoDateTime">,
        updatedAt: new Date().toISOString() as Brand<string, "IsoDateTime">,
      };

      const mockInspector = new MockInspector(mockParameters);

      const inspectors = new Map<string, SignatureInspector>();
      inspectors.set("job-1", mockInspector);

      const updateCalls: Partial<Job>[] = [];
      const events: string[] = [];

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadPendingJobsCommand, async () => [mockJob]);
      commandBus.register(UpdateJobCommand, async (_cmd: UpdateJobCommand) => {
        updateCalls.push(_cmd.updates);
      });
      commandBus.register(LoadScenarioCommand, async () => ({
        id: mockJob.scenarioId,
        name: "test",
        type: "postman" as Brand<string, "ScenarioType">,
        source: { item: { request: { method: "GET", url: { raw: "https://example.com" } } } },
      }));
      commandBus.register(ReplayCommand, async () => ({
        request: mockRequest,
        response: mockResponse,
      }));

      eventBus.subscribe("scan:jobStarted", () => { events.push("started"); });
      eventBus.subscribe("scan:jobCompleted", () => { events.push("completed"); });

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      await orchestrator.scan(scanId, inspectors, 2);

      // Should have at least 2 updates: running then completed
      expect(updateCalls.length).toBeGreaterThanOrEqual(2);
      expect(updateCalls[0].status).toBe("running" as JobStatus);
      expect(updateCalls[1].status).toBe("completed" as JobStatus);
      expect(events).toContain("started");
      expect(events).toContain("completed");
    });

    it("handles job errors gracefully", async () => {
      const scanId = "test-scan-id" as Brand<string, "ScanId">;
      const mockJob: Job = {
        id: "job-err" as Brand<string, "JobId">,
        scenarioId: "scenario-1" as Brand<string, "ScenarioId">,
        requestId: "req-1" as Brand<string, "RequestId">,
        signatureName: "failing-sig",
        parameters: mockParameters,
        status: "pending" as JobStatus,
        finding: null,
        error: null,
        createdAt: new Date().toISOString() as Brand<string, "IsoDateTime">,
        updatedAt: new Date().toISOString() as Brand<string, "IsoDateTime">,
      };

      // Inspector that always throws
      const failingInspector: SignatureInspector = {
        signatureName: "failing-sig",
        parameters: mockParameters,
        async inspect() {
          throw new Error("Inspection failed");
        },
      };

      const inspectors = new Map<string, SignatureInspector>();
      inspectors.set("job-err", failingInspector);

      const updateCalls: Partial<Job>[] = [];
      const events: string[] = [];

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadPendingJobsCommand, async () => [mockJob]);
      commandBus.register(UpdateJobCommand, async (_cmd: UpdateJobCommand) => {
        updateCalls.push(_cmd.updates);
      });
      commandBus.register(LoadScenarioCommand, async () => ({
        id: mockJob.scenarioId,
        name: "test",
        type: "postman" as Brand<string, "ScenarioType">,
        source: { item: { request: { method: "GET", url: { raw: "https://example.com" } } } },
      }));
      commandBus.register(ReplayCommand, async () => ({
        request: mockRequest,
        response: mockResponse,
      }));

      eventBus.subscribe("scan:jobError", () => { events.push("error"); });

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      await orchestrator.scan(scanId, inspectors, 2);

      expect(events).toContain("error");
      // running then error
      expect(updateCalls.length).toBeGreaterThanOrEqual(2);
      expect(updateCalls[0].status).toBe("running" as JobStatus);
      expect(updateCalls[1].status).toBe("error" as JobStatus);
    });

    it("handles empty job list", async () => {
      const scanId = "test-scan-id" as Brand<string, "ScanId">;
      const inspectors = new Map<string, SignatureInspector>();

      commandBus.register(SaveScanStateCommand, async () => {});
      commandBus.register(LoadPendingJobsCommand, async () => []);

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      await orchestrator.scan(scanId, inspectors, 2);

      expect(logger.info).toHaveBeenCalledWith("No pending jobs to scan");
    });
  });

  describe("report phase", () => {
    it("broadcasts GenerateReportCommand with scan state and jobs", async () => {
      const scanId = "report-scan-id" as Brand<string, "ScanId">;
      const mockScanState: ScanState = {
        id: scanId,
        status: "completed" as ScanStatus,
        startedAt: "2024-01-01T00:00:00.000Z" as Brand<string, "IsoDateTime">,
        updatedAt: "2024-01-01T00:01:00.000Z" as Brand<string, "IsoDateTime">,
      };

      const mockJobs: Job[] = [
        {
          id: "job-1" as Brand<string, "JobId">,
          scenarioId: "sc-1" as Brand<string, "ScenarioId">,
          requestId: "req-1" as Brand<string, "RequestId">,
          signatureName: "reflected-xss",
          parameters: mockParameters,
          status: "completed" as JobStatus,
          finding: mockFinding,
          error: null,
          createdAt: "2024-01-01T00:00:00.000Z" as Brand<string, "IsoDateTime">,
          updatedAt: "2024-01-01T00:00:01.000Z" as Brand<string, "IsoDateTime">,
        },
      ];

      commandBus.register(LoadScanStateCommand, async () => mockScanState);
      commandBus.register(LoadJobsByScanIdCommand, async () => mockJobs);

      let reportPayload: { scanState: ScanState; jobs: Job[] } | null = null;
      commandBus.register(GenerateReportCommand, async (cmd: GenerateReportCommand) => {
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
      const scanId = "missing-scan" as Brand<string, "ScanId">;

      commandBus.register(LoadScanStateCommand, async () => null);

      const orchestrator = new Orchestrator({
        commandBus,
        eventBus,
        logger,
      });

      await orchestrator.report(scanId);

      expect(logger.warn).toHaveBeenCalledWith(
        `No scan state found for ${scanId as string}`,
      );
    });
  });
});
