import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { JsonStoragePlugin } from "./json-storage.ts";
import {
  SaveJobCommand,
  LoadJobCommand,
  LoadJobsByStatusCommand,
  UpdateJobCommand,
  SaveScanStateCommand,
  LoadScanStateCommand,
  LoadScenarioCommand,
} from "../../commands/storage.ts";
import {
  SaveExchangeCommand,
  LoadExchangesCommand,
} from "../../commands/exchange.ts";
import {
  type SignatureJob,
  type ScanState,
  type Scenario,
  type Exchange,
  SignatureJobStatus,
  ScanStatus,
} from "../../types/models.ts";
import { QueryParameter } from "../parameter/query.ts";
import {
  ScanId,
  SignatureJobId,
  ScenarioId,
  ExchangeId,
  ReplayId,

} from "../../types/branded.ts";

// --- Fixture factories ---
function makeJob(overrides: Partial<SignatureJob> = {}): SignatureJob {
  return {
    id: SignatureJobId("job-1"),
    scanId: ScanId("test-scan-id"),
    scenarioId: ScenarioId("scan-1"),
    signatureName: "signature:sig-1",
    groups: [],
    parameter: new QueryParameter({ name: "" }, "", []),
    status: SignatureJobStatus.Pending,
    finding: null,
    error: null,
    createdAt: new Date("2025-01-01T00:00:00Z"),
    updatedAt: new Date("2025-01-01T00:00:00Z"),
    ...overrides,
  };
}

function makeScanState(overrides: Partial<ScanState> = {}): ScanState {
  return {
    id: ScanId("scan-1"),
    status: ScanStatus.Scanning,
    startedAt: new Date("2025-01-01T00:00:00Z"),
    updatedAt: new Date("2025-01-01T00:00:00Z"),
    ...overrides,
  };
}

function makeScenario(overrides: Partial<Scenario> = {}): Scenario {
  return {
    id: ScenarioId("scenario-1"),
    name: "Test Scenario",
    type: "xss" as any,
    source: null,
    representation: "  Test Scenario",
    diffStrategy: { type: "exact" },
    ...overrides,
  };
}

// --- Test setup ---
let tempDir: string;
let commandBus: InMemoryCommandBus;
const noopLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `gevanni-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  commandBus = new InMemoryCommandBus();

  const plugin = new JsonStoragePlugin({ outputDir: tempDir });
  await plugin.init({
    commandBus,
    eventBus: new InMemoryEventBus(),
    logger: noopLogger,
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

      const loaded: SignatureJob | null = await commandBus.dispatch(
        new LoadJobCommand(job.id),
      );
      expect(loaded).toEqual(job);
    });

    it("returns null when job does not exist", async () => {
      const result: SignatureJob | null = await commandBus.dispatch(
        new LoadJobCommand(SignatureJobId("nonexistent")),
      );
      expect(result).toBeNull();
    });

    it("saves multiple jobs and retrieves each", async () => {
      const job1 = makeJob({ id: SignatureJobId("job-1") });
      const job2 = makeJob({
        id: SignatureJobId("job-2"),
        signatureName: "signature:sig-2",
      });

      await commandBus.dispatch(new SaveJobCommand(job1));
      await commandBus.dispatch(new SaveJobCommand(job2));

      const loaded1: SignatureJob | null = await commandBus.dispatch(
        new LoadJobCommand(SignatureJobId("job-1")),
      );
      const loaded2: SignatureJob | null = await commandBus.dispatch(
        new LoadJobCommand(SignatureJobId("job-2")),
      );

      expect(loaded1).toEqual(job1);
      expect(loaded2).toEqual(job2);
    });
  });

  describe("LoadJobsByStatusCommand", () => {
    it("returns all jobs when no status filter is given", async () => {
      const scanId = ScanId("scan-1");
      const job1 = makeJob({
        id: SignatureJobId("job-1"),
        scanId: ScanId("scan-1"),
        scenarioId: ScenarioId("scan-1"),
      });
      const job2 = makeJob({
        id: SignatureJobId("job-2"),
        scanId: ScanId("scan-1"),
        scenarioId: ScenarioId("scan-1"),
      });

      await commandBus.dispatch(new SaveJobCommand(job1));
      await commandBus.dispatch(new SaveJobCommand(job2));

      const jobs: SignatureJob[] = await commandBus.dispatch(
        new LoadJobsByStatusCommand(scanId),
      );
      expect(jobs).toHaveLength(2);
      expect(jobs).toEqual(expect.arrayContaining([job1, job2]));
    });

    it("returns empty array when no jobs exist for scan", async () => {
      const jobs: SignatureJob[] = await commandBus.dispatch(
        new LoadJobsByStatusCommand(ScanId("empty-scan")),
      );
      expect(jobs).toEqual([]);
    });
  });

  describe("LoadJobsByStatusCommand with status filter", () => {
    it("returns only pending jobs when filter is [Pending]", async () => {
      const scanId = ScanId("scan-1");
      const pendingJob = makeJob({
        id: SignatureJobId("job-pending"),
        scanId: ScanId("scan-1"),
        scenarioId: ScenarioId("scan-1"),
        status: SignatureJobStatus.Pending,
      });
      const completedJob = makeJob({
        id: SignatureJobId("job-completed"),
        scanId: ScanId("scan-1"),
        scenarioId: ScenarioId("scan-1"),
        status: SignatureJobStatus.Completed,
      });
      const errorJob = makeJob({
        id: SignatureJobId("job-error"),
        scanId: ScanId("scan-1"),
        scenarioId: ScenarioId("scan-1"),
        status: SignatureJobStatus.Error,
      });

      await commandBus.dispatch(new SaveJobCommand(pendingJob));
      await commandBus.dispatch(new SaveJobCommand(completedJob));
      await commandBus.dispatch(new SaveJobCommand(errorJob));

      const pending: SignatureJob[] = await commandBus.dispatch(
        new LoadJobsByStatusCommand(scanId, [SignatureJobStatus.Pending]),
      );
      expect(pending).toHaveLength(1);
      expect(pending[0].id).toBe(SignatureJobId("job-pending"));
    });

    it("returns only completed jobs when filter is [Completed]", async () => {
      const scanId = ScanId("scan-1");
      const pendingJob = makeJob({
        id: SignatureJobId("job-pending"),
        scanId: ScanId("scan-1"),
        scenarioId: ScenarioId("scan-1"),
        status: SignatureJobStatus.Pending,
      });
      const completedJob = makeJob({
        id: SignatureJobId("job-completed"),
        scanId: ScanId("scan-1"),
        scenarioId: ScenarioId("scan-1"),
        status: SignatureJobStatus.Completed,
      });
      const errorJob = makeJob({
        id: SignatureJobId("job-error"),
        scanId: ScanId("scan-1"),
        scenarioId: ScenarioId("scan-1"),
        status: SignatureJobStatus.Error,
      });

      await commandBus.dispatch(new SaveJobCommand(pendingJob));
      await commandBus.dispatch(new SaveJobCommand(completedJob));
      await commandBus.dispatch(new SaveJobCommand(errorJob));

      const completed: SignatureJob[] = await commandBus.dispatch(
        new LoadJobsByStatusCommand(scanId, [SignatureJobStatus.Completed]),
      );
      expect(completed).toHaveLength(1);
      expect(completed[0].id).toBe(SignatureJobId("job-completed"));
    });

    it("returns multiple statuses when filter has multiple values", async () => {
      const scanId = ScanId("scan-1");
      const pendingJob = makeJob({
        id: SignatureJobId("job-pending"),
        scanId: ScanId("scan-1"),
        scenarioId: ScenarioId("scan-1"),
        status: SignatureJobStatus.Pending,
      });
      const completedJob = makeJob({
        id: SignatureJobId("job-completed"),
        scanId: ScanId("scan-1"),
        scenarioId: ScenarioId("scan-1"),
        status: SignatureJobStatus.Completed,
      });

      await commandBus.dispatch(new SaveJobCommand(pendingJob));
      await commandBus.dispatch(new SaveJobCommand(completedJob));

      const jobs: SignatureJob[] = await commandBus.dispatch(
        new LoadJobsByStatusCommand(scanId, [
          SignatureJobStatus.Pending,
          SignatureJobStatus.Completed,
        ]),
      );
      expect(jobs).toHaveLength(2);
    });

    it("returns empty array when no matching jobs exist", async () => {
      const scanId = ScanId("scan-1");
      const completedJob = makeJob({
        id: SignatureJobId("job-1"),
        scanId: ScanId("scan-1"),
        scenarioId: ScenarioId("scan-1"),
        status: SignatureJobStatus.Completed,
      });
      await commandBus.dispatch(new SaveJobCommand(completedJob));

      const pending: SignatureJob[] = await commandBus.dispatch(
        new LoadJobsByStatusCommand(scanId, [SignatureJobStatus.Pending]),
      );
      expect(pending).toEqual([]);
    });
  });

  describe("UpdateJobCommand", () => {
    it("updates job status", async () => {
      const job = makeJob({ status: SignatureJobStatus.Pending });
      await commandBus.dispatch(new SaveJobCommand(job));

      const newStatus = SignatureJobStatus.Running;
      await commandBus.dispatch(
        new UpdateJobCommand(job.id, { status: newStatus }),
      );

      const loaded: SignatureJob | null = await commandBus.dispatch(
        new LoadJobCommand(job.id),
      );
      expect(loaded!.status).toBe(newStatus);
    });

    it("preserves fields not included in updates", async () => {
      const job = makeJob({ signatureName: "signature:original" });
      await commandBus.dispatch(new SaveJobCommand(job));

      await commandBus.dispatch(
        new UpdateJobCommand(job.id, {
          status: SignatureJobStatus.Completed,
        }),
      );

      const loaded: SignatureJob | null = await commandBus.dispatch(
        new LoadJobCommand(job.id),
      );
      expect(loaded!.signatureName).toBe("signature:original");
      expect(loaded!.status).toBe(SignatureJobStatus.Completed);
    });

    it("throws when job not found", async () => {
      await expect(
        commandBus.dispatch(
          new UpdateJobCommand(SignatureJobId("nonexistent"), {
            status: SignatureJobStatus.Running,
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
        new LoadScanStateCommand(ScanId("nonexistent")),
      );
      expect(loaded).toBeNull();
    });

    it("returns latest incomplete scan when no scanId provided", async () => {
      // Create two scans: one completed, one in progress
      const completedScan = makeScanState({
        id: ScanId("scan-completed"),
        status: ScanStatus.Completed,
        updatedAt: new Date("2025-01-02T00:00:00Z"),
      });
      const activeScan = makeScanState({
        id: ScanId("scan-active"),
        status: ScanStatus.Scanning,
        updatedAt: new Date("2025-01-01T00:00:00Z"),
      });

      await commandBus.dispatch(new SaveScanStateCommand(completedScan));
      await commandBus.dispatch(new SaveScanStateCommand(activeScan));

      const loaded: ScanState | null = await commandBus.dispatch(
        new LoadScanStateCommand(ScanId("")),
      );
      expect(loaded).not.toBeNull();
      expect(loaded!.id).toBe(ScanId("scan-active"));
    });

    it("returns null when all scans are completed and no scanId provided", async () => {
      const completedScan = makeScanState({
        id: ScanId("scan-done"),
        status: ScanStatus.Completed,
      });
      await commandBus.dispatch(new SaveScanStateCommand(completedScan));

      const loaded: ScanState | null = await commandBus.dispatch(
        new LoadScanStateCommand(ScanId("")),
      );
      expect(loaded).toBeNull();
    });
  });

  describe("LoadScenarioCommand", () => {
    it("retrieves a saved scenario", async () => {
      const scenario = makeScenario({ id: ScenarioId("scenario-1") });

      // Write scenario.json directly since there is no SaveScenarioCommand
      const scenarioPath = join(tempDir, "scan-1", "scenario.json");
      await fs.mkdir(join(tempDir, "scan-1"), { recursive: true });
      await fs.writeFile(scenarioPath, JSON.stringify(scenario, null, 2));

      const loaded: Scenario = await commandBus.dispatch(
        new LoadScenarioCommand(ScenarioId("scenario-1")),
      );
      expect(loaded).toMatchObject({
        id: scenario.id,
        name: scenario.name,
        type: scenario.type,
        source: scenario.source,
      });
      expect(loaded.representation).toBe(scenario.representation);
    });

    it("throws when scenario not found", async () => {
      await expect(
        commandBus.dispatch(new LoadScenarioCommand(ScenarioId("nonexistent"))),
      ).rejects.toThrow("Scenario not found");
    });
  });

  describe("SaveExchangeCommand / LoadExchangesCommand", () => {
    const exchange: Exchange = {
      id: ExchangeId("exchange-001"),
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
      const replayId = ReplayId("test-replay-001");
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
        new LoadExchangesCommand(ReplayId("nonexistent-id")),
      );
      expect(loaded).toEqual([]);
    });

    it("accumulates multiple exchanges for same replayId", async () => {
      const replayId = ReplayId("test-replay-002");
      await commandBus.dispatch(new SaveExchangeCommand(replayId, exchange));
      const exchange2: Exchange = {
        id: ExchangeId("exchange-002"),
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
