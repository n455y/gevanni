import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { JsonStoragePlugin } from "./json-storage.js";
import {
  SaveJobCommand,
  LoadJobCommand,
  LoadJobsByScanIdCommand,
  LoadPendingJobsCommand,
  UpdateJobCommand,
  SaveScanStateCommand,
  LoadScanStateCommand,
  LoadScenarioCommand,
} from "../../commands/storage.js";
import {
  SaveExchangeCommand,
  LoadExchangesCommand,
} from "../../commands/exchange.js";
import type { Job, ScanState, Scenario, Exchange } from "../../types/models.js";
import type {
  ScanId,
  JobId,
  ScenarioId,
  JobStatus,
  ScanStatus,
  IsoDateTime,
} from "../../types/branded.js";

// --- Branding helpers ---
const asScanId = (s: string) => s as ScanId;
const asJobId = (s: string) => s as JobId;
const asScenarioId = (s: string) => s as ScenarioId;
const asJobStatus = (s: string) => s as JobStatus;
const asScanStatus = (s: string) => s as ScanStatus;
const asIsoDateTime = (s: string) => s as IsoDateTime;

// --- Fixture factories ---
function makeJob(overrides: Partial<Job> = {}): Job {
  return {
    id: asJobId("job-1"),
    scenarioId: asScenarioId("scan-1"),
    requestId: "req-1" as any,
    signatureName: "sig-1",
    parameters: [],
    status: asJobStatus("pending"),
    finding: null,
    error: null,
    createdAt: asIsoDateTime("2025-01-01T00:00:00Z"),
    updatedAt: asIsoDateTime("2025-01-01T00:00:00Z"),
    ...overrides,
  };
}

function makeScanState(overrides: Partial<ScanState> = {}): ScanState {
  return {
    id: asScanId("scan-1"),
    status: asScanStatus("scanning"),
    startedAt: asIsoDateTime("2025-01-01T00:00:00Z"),
    updatedAt: asIsoDateTime("2025-01-01T00:00:00Z"),
    ...overrides,
  };
}

function makeScenario(overrides: Partial<Scenario> = {}): Scenario {
  return {
    id: asScenarioId("scenario-1"),
    name: "Test Scenario",
    type: "xss" as any,
    source: null,
    ...overrides,
  };
}

// --- Test setup ---
let tempDir: string;
let commandBus: InMemoryCommandBus;

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `gevanni-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  commandBus = new InMemoryCommandBus();

  const plugin = new JsonStoragePlugin();
  await plugin.init({
    commandBus,
    eventBus: new InMemoryEventBus(),
    config: { outputDir: tempDir },
  });
});

afterEach(async () => {
  await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
});

describe("JsonStoragePlugin", () => {
  describe("SaveJobCommand / LoadJobCommand", () => {
    it("saves a job and retrieves it by id", async () => {
      const job = makeJob();
      await commandBus.dispatch(new SaveJobCommand(job));

      const loaded: Job | null = await commandBus.dispatch(
        new LoadJobCommand(job.id),
      );
      expect(loaded).toEqual(job);
    });

    it("returns null when job does not exist", async () => {
      const result: Job | null = await commandBus.dispatch(
        new LoadJobCommand(asJobId("nonexistent")),
      );
      expect(result).toBeNull();
    });

    it("saves multiple jobs and retrieves each", async () => {
      const job1 = makeJob({ id: asJobId("job-1") });
      const job2 = makeJob({ id: asJobId("job-2"), signatureName: "sig-2" });

      await commandBus.dispatch(new SaveJobCommand(job1));
      await commandBus.dispatch(new SaveJobCommand(job2));

      const loaded1: Job | null = await commandBus.dispatch(
        new LoadJobCommand(asJobId("job-1")),
      );
      const loaded2: Job | null = await commandBus.dispatch(
        new LoadJobCommand(asJobId("job-2")),
      );

      expect(loaded1).toEqual(job1);
      expect(loaded2).toEqual(job2);
    });
  });

  describe("LoadJobsByScanIdCommand", () => {
    it("returns all jobs for a given scan", async () => {
      const scanId = asScanId("scan-1");
      const job1 = makeJob({
        id: asJobId("job-1"),
        scenarioId: asScenarioId("scan-1"),
      });
      const job2 = makeJob({
        id: asJobId("job-2"),
        scenarioId: asScenarioId("scan-1"),
      });

      await commandBus.dispatch(new SaveJobCommand(job1));
      await commandBus.dispatch(new SaveJobCommand(job2));

      const jobs: Job[] = await commandBus.dispatch(
        new LoadJobsByScanIdCommand(scanId),
      );
      expect(jobs).toHaveLength(2);
      expect(jobs).toEqual(expect.arrayContaining([job1, job2]));
    });

    it("returns empty array when no jobs exist for scan", async () => {
      const jobs: Job[] = await commandBus.dispatch(
        new LoadJobsByScanIdCommand(asScanId("empty-scan")),
      );
      expect(jobs).toEqual([]);
    });
  });

  describe("LoadPendingJobsCommand", () => {
    it("returns only pending jobs", async () => {
      const scanId = asScanId("scan-1");
      const pendingJob = makeJob({
        id: asJobId("job-pending"),
        scenarioId: asScenarioId("scan-1"),
        status: asJobStatus("pending"),
      });
      const completedJob = makeJob({
        id: asJobId("job-completed"),
        scenarioId: asScenarioId("scan-1"),
        status: asJobStatus("completed"),
      });
      const errorJob = makeJob({
        id: asJobId("job-error"),
        scenarioId: asScenarioId("scan-1"),
        status: asJobStatus("error"),
      });

      await commandBus.dispatch(new SaveJobCommand(pendingJob));
      await commandBus.dispatch(new SaveJobCommand(completedJob));
      await commandBus.dispatch(new SaveJobCommand(errorJob));

      const pending: Job[] = await commandBus.dispatch(
        new LoadPendingJobsCommand(scanId),
      );
      expect(pending).toHaveLength(1);
      expect(pending[0].id).toBe(asJobId("job-pending"));
    });

    it("returns empty array when no pending jobs exist", async () => {
      const scanId = asScanId("scan-1");
      const completedJob = makeJob({
        id: asJobId("job-1"),
        scenarioId: asScenarioId("scan-1"),
        status: asJobStatus("completed"),
      });
      await commandBus.dispatch(new SaveJobCommand(completedJob));

      const pending: Job[] = await commandBus.dispatch(
        new LoadPendingJobsCommand(scanId),
      );
      expect(pending).toEqual([]);
    });
  });

  describe("UpdateJobCommand", () => {
    it("updates job status", async () => {
      const job = makeJob({ status: asJobStatus("pending") });
      await commandBus.dispatch(new SaveJobCommand(job));

      const newStatus = asJobStatus("running");
      await commandBus.dispatch(
        new UpdateJobCommand(job.id, { status: newStatus }),
      );

      const loaded: Job | null = await commandBus.dispatch(
        new LoadJobCommand(job.id),
      );
      expect(loaded!.status).toBe(newStatus);
    });

    it("preserves fields not included in updates", async () => {
      const job = makeJob({ signatureName: "original" });
      await commandBus.dispatch(new SaveJobCommand(job));

      await commandBus.dispatch(
        new UpdateJobCommand(job.id, {
          status: asJobStatus("completed"),
        }),
      );

      const loaded: Job | null = await commandBus.dispatch(
        new LoadJobCommand(job.id),
      );
      expect(loaded!.signatureName).toBe("original");
      expect(loaded!.status).toBe(asJobStatus("completed"));
    });

    it("throws when job not found", async () => {
      await expect(
        commandBus.dispatch(
          new UpdateJobCommand(asJobId("nonexistent"), {
            status: asJobStatus("running"),
          }),
        ),
      ).rejects.toThrow("Job not found");
    });
  });

  describe("SaveScanStateCommand / LoadScanStateCommand", () => {
    it("saves and retrieves scan state by id", async () => {
      const state = makeScanState();
      await commandBus.dispatch(new SaveScanStateCommand(state));

      const loaded: ScanState | null = await commandBus.dispatch(
        new LoadScanStateCommand(state.id),
      );
      expect(loaded).toEqual(state);
    });

    it("returns null when state does not exist", async () => {
      const loaded: ScanState | null = await commandBus.dispatch(
        new LoadScanStateCommand(asScanId("nonexistent")),
      );
      expect(loaded).toBeNull();
    });

    it("returns latest incomplete scan when no scanId provided", async () => {
      // Create two scans: one completed, one in progress
      const completedScan = makeScanState({
        id: asScanId("scan-completed"),
        status: asScanStatus("completed"),
        updatedAt: asIsoDateTime("2025-01-02T00:00:00Z"),
      });
      const activeScan = makeScanState({
        id: asScanId("scan-active"),
        status: asScanStatus("scanning"),
        updatedAt: asIsoDateTime("2025-01-01T00:00:00Z"),
      });

      await commandBus.dispatch(new SaveScanStateCommand(completedScan));
      await commandBus.dispatch(new SaveScanStateCommand(activeScan));

      const loaded: ScanState | null = await commandBus.dispatch(
        new LoadScanStateCommand("" as ScanId),
      );
      expect(loaded).not.toBeNull();
      expect(loaded!.id).toBe(asScanId("scan-active"));
    });

    it("returns null when all scans are completed and no scanId provided", async () => {
      const completedScan = makeScanState({
        id: asScanId("scan-done"),
        status: asScanStatus("completed"),
      });
      await commandBus.dispatch(new SaveScanStateCommand(completedScan));

      const loaded: ScanState | null = await commandBus.dispatch(
        new LoadScanStateCommand("" as ScanId),
      );
      expect(loaded).toBeNull();
    });
  });

  describe("LoadScenarioCommand", () => {
    it("retrieves a saved scenario", async () => {
      const scenario = makeScenario({ id: asScenarioId("scenario-1") });

      // Write scenario.json directly since there is no SaveScenarioCommand
      const scenarioPath = join(tempDir, "scan-1", "scenario.json");
      await fs.mkdir(join(tempDir, "scan-1"), { recursive: true });
      await fs.writeFile(scenarioPath, JSON.stringify(scenario, null, 2));

      const loaded: Scenario = await commandBus.dispatch(
        new LoadScenarioCommand(asScenarioId("scenario-1")),
      );
      expect(loaded).toEqual(scenario);
    });

    it("throws when scenario not found", async () => {
      await expect(
        commandBus.dispatch(
          new LoadScenarioCommand(asScenarioId("nonexistent")),
        ),
      ).rejects.toThrow("Scenario not found");
    });
  });

  describe("SaveExchangeCommand / LoadExchangesCommand", () => {
    const exchange: Exchange = {
      request: {
        method: "GET",
        url: "http://example.com/test",
        headers: { "content-type": "text/plain" },
        body: null,
      },
      response: {
        statusCode: 200,
        headers: { "content-type": "text/plain" },
        body: Buffer.from("ok"),
      },
    };

    it("saves and loads exchanges by replayId", async () => {
      const replayId = "test-replay-001";
      await commandBus.dispatch(new SaveExchangeCommand(replayId, exchange));
      const loaded: Exchange[] = await commandBus.dispatch(
        new LoadExchangesCommand(replayId),
      );
      expect(loaded).toHaveLength(1);
      expect(loaded[0].request.method).toBe("GET");
      expect(loaded[0].response.statusCode).toBe(200);
    });

    it("returns empty array when no exchanges exist", async () => {
      const loaded: Exchange[] = await commandBus.dispatch(
        new LoadExchangesCommand("nonexistent-id"),
      );
      expect(loaded).toEqual([]);
    });

    it("accumulates multiple exchanges for same replayId", async () => {
      const replayId = "test-replay-002";
      await commandBus.dispatch(new SaveExchangeCommand(replayId, exchange));
      const exchange2: Exchange = {
        request: {
          method: "POST",
          url: "http://example.com/submit",
          headers: {},
          body: Buffer.from("data"),
        },
        response: { statusCode: 201, headers: {}, body: null },
      };
      await commandBus.dispatch(new SaveExchangeCommand(replayId, exchange2));
      const loaded: Exchange[] = await commandBus.dispatch(
        new LoadExchangesCommand(replayId),
      );
      expect(loaded).toHaveLength(2);
    });
  });
});
