import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { JsonReporterPlugin } from "./json-reporter.js";
import { GenerateReportCommand } from "../../commands/report.js";
import { InspectionParameter, type Job, type ScanState } from "../../types/models.js";
import type {
  ScanId,
  JobId,
  ScenarioId,
  RequestId,
  JobStatus,
  ScanStatus,
  IsoDateTime,
  Evidence,
} from "../../types/branded.js";

// --- Branding helpers ---
const asScanId = (s: string) => s as ScanId;
const asJobId = (s: string) => s as JobId;
const asScenarioId = (s: string) => s as ScenarioId;
const asRequestId = (s: string) => s as RequestId;
const asJobStatus = (s: string) => s as JobStatus;
const asScanStatus = (s: string) => s as ScanStatus;
const asIsoDateTime = (s: string) => s as IsoDateTime;
const asEvidence = (s: string) => s as Evidence;

// --- Fixture factories ---
function makeScanState(overrides: Partial<ScanState> = {}): ScanState {
  return {
    id: asScanId("scan-1"),
    status: asScanStatus("scanning"),
    startedAt: asIsoDateTime("2025-01-01T00:00:00Z"),
    updatedAt: asIsoDateTime("2025-01-01T00:00:00Z"),
    ...overrides,
  };
}

function makeJob(overrides: Partial<Job> = {}): Job {
  return {
    id: asJobId("job-1"),
    scanId: asScanId("test-scan-id"),
    scenarioId: asScenarioId("scan-1"),
    requestId: asRequestId("req-1"),
    signatureName: "reflected-xss",
    parameter: new InspectionParameter({ name: "" }, "", []),
    status: asJobStatus("completed"),
    finding: null,
    error: null,
    createdAt: asIsoDateTime("2025-01-01T00:00:00Z"),
    updatedAt: asIsoDateTime("2025-01-01T00:00:00Z"),
    ...overrides,
  };
}

// --- Test setup ---
let tempDir: string;
let commandBus: InMemoryCommandBus;

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `gevanni-test-reporter-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  commandBus = new InMemoryCommandBus();
});

afterEach(async () => {
  await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
});

describe("JsonReporterPlugin", () => {
  it("writes report to the configured output path", async () => {
    const outputPath = join(tempDir, "report.json");

    const plugin = new JsonReporterPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: { outputPath },
    });

    const scanState = makeScanState({
      id: asScanId("scan-abc"),
    });
    const jobs: Job[] = [
      makeJob({ id: asJobId("job-1") }),
    ];

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs }),
    );

    const raw = await fs.readFile(outputPath, "utf-8");
    const report = JSON.parse(raw);

    expect(report.scanState).toEqual(scanState);
    expect(report.jobs).toEqual(jobs);
    expect(report.summary).toEqual({
      total: 1,
      vulnerable: 0,
      safe: 1,
      errors: 0,
    });
  });

  it("uses auto-generated path based on scan ID when no outputPath configured", async () => {
    const plugin = new JsonReporterPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const scanState = makeScanState({
      id: asScanId("scan-auto"),
    });

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [] }),
    );

    const expectedPath = "gevanni-report-scan-auto.json";
    const raw = await fs.readFile(expectedPath, "utf-8");
    const report = JSON.parse(raw);

    expect(report.scanState.id).toBe("scan-auto" as ScanId);
    expect(report.summary.total).toBe(0);

    // Cleanup
    await fs.unlink(expectedPath);
  });

  it("computes correct summary for mixed job statuses", async () => {
    const outputPath = join(tempDir, "mixed-report.json");

    const plugin = new JsonReporterPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: { outputPath },
    });

    const scanState = makeScanState();
    const jobs: Job[] = [
      makeJob({
        id: asJobId("j1"),
        status: asJobStatus("completed"),
        finding: {
          vulnerable: true,
          evidence: asEvidence("XSS found"),
          request: { method: "GET", url: "https://example.com", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        },
      }),
      makeJob({
        id: asJobId("j2"),
        status: asJobStatus("completed"),
        finding: {
          vulnerable: false,
          evidence: asEvidence(""),
          request: { method: "GET", url: "https://example.com", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        },
      }),
      makeJob({
        id: asJobId("j3"),
        status: asJobStatus("error"),
        error: "Connection refused" as any,
      }),
      makeJob({
        id: asJobId("j4"),
        status: asJobStatus("completed"),
        finding: {
          vulnerable: true,
          evidence: asEvidence("SQL error"),
          request: { method: "POST", url: "https://example.com/api", headers: {}, body: null },
          response: { statusCode: 500, headers: {}, body: null },
        },
      }),
    ];

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs }),
    );

    const raw = await fs.readFile(outputPath, "utf-8");
    const report = JSON.parse(raw);

    expect(report.summary).toEqual({
      total: 4,
      vulnerable: 2,
      safe: 1,
      errors: 1,
    });
  });

  it("handles empty jobs list", async () => {
    const outputPath = join(tempDir, "empty-report.json");

    const plugin = new JsonReporterPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: { outputPath },
    });

    const scanState = makeScanState();

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [] }),
    );

    const raw = await fs.readFile(outputPath, "utf-8");
    const report = JSON.parse(raw);

    expect(report.scanState).toEqual(scanState);
    expect(report.jobs).toEqual([]);
    expect(report.summary).toEqual({
      total: 0,
      vulnerable: 0,
      safe: 0,
      errors: 0,
    });
  });

  it("creates output directory if it does not exist", async () => {
    const nestedDir = join(tempDir, "nested", "dir");
    const outputPath = join(nestedDir, "report.json");

    const plugin = new JsonReporterPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: { outputPath },
    });

    const scanState = makeScanState();

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [] }),
    );

    const raw = await fs.readFile(outputPath, "utf-8");
    const report = JSON.parse(raw);

    expect(report).toBeDefined();
    expect(report.summary.total).toBe(0);
  });
});
