import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import JsonReporterPlugin from "./json-reporter.ts";
import { GenerateReportCommand } from "../../commands/report.ts";
import {
  serializeSignatureJob,
  serializeScanState,
  type SignatureJob,
  type ScanState,
  SignatureJobStatus,
  ScanStatus,
} from "../../types/models.ts";
import { QueryParameter } from "../parameter/query/model.ts";
import {
  ScanId,
  SignatureJobId,
  ScenarioId,
  ExchangeId,

} from "../../types/branded.ts";

// --- Fixture factories ---
function makeScanState(overrides: Partial<ScanState> = {}): ScanState {
  return {
    id: ScanId("scan-1"),
    status: ScanStatus.Scanning,
    startedAt: new Date("2025-01-01T00:00:00Z"),
    updatedAt: new Date("2025-01-01T00:00:00Z"),
    ...overrides,
  };
}

function makeJob(overrides: Partial<SignatureJob> = {}): SignatureJob {
  return {
    id: SignatureJobId("job-1"),
    scanId: ScanId("test-scan-id"),
    scenarioId: ScenarioId("scan-1"),
    signatureName: "signature:reflected-xss",
    groups: [],
    parameter: new QueryParameter({ name: "" }, "", []),
    status: SignatureJobStatus.Completed,
    finding: null,
    error: null,
    createdAt: new Date("2025-01-01T00:00:00Z"),
    updatedAt: new Date("2025-01-01T00:00:00Z"),
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

    const plugin = new JsonReporterPlugin({ outputPath });
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const scanState = makeScanState({
      id: ScanId("scan-abc"),
    });
    const jobs: SignatureJob[] = [makeJob({ id: SignatureJobId("job-1") })];

    await commandBus.broadcast(new GenerateReportCommand({ scanState, jobs }));

    const raw = await fs.readFile(outputPath, "utf-8");
    const report = JSON.parse(raw);

    expect(report.scanState).toEqual(serializeScanState(scanState));
    expect(report.jobs).toEqual(jobs.map(serializeSignatureJob));
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
      logger: noopLogger,
    });

    const scanState = makeScanState({
      id: ScanId("scan-auto"),
    });

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [] }),
    );

    const expectedPath = "gevanni-report-scan-auto.json";
    const raw = await fs.readFile(expectedPath, "utf-8");
    const report = JSON.parse(raw);

    expect(report.scanState.id).toBe(ScanId("scan-auto"));
    expect(report.summary.total).toBe(0);

    // Cleanup
    await fs.unlink(expectedPath);
  });

  it("computes correct summary for mixed job statuses", async () => {
    const outputPath = join(tempDir, "mixed-report.json");

    const plugin = new JsonReporterPlugin({ outputPath });
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const scanState = makeScanState();
    const jobs: SignatureJob[] = [
      makeJob({
        id: SignatureJobId("j1"),
        status: SignatureJobStatus.Completed,
        finding: {
          vulnerable: true,
          evidence: {
            judgmentId: "payload-reflection",
            exchanges: [],
            evidenceExchanges: [],
          },
          request: {
            method: "GET",
            url: "https://example.com",
            headers: {},
            body: null,
          },
          response: { statusCode: 200, headers: {}, body: null },
        },
      }),
      makeJob({
        id: SignatureJobId("j2"),
        status: SignatureJobStatus.Completed,
        finding: {
          vulnerable: false,
          evidence: {
            judgmentId: "sql-error-pattern",
            exchanges: [],
            evidenceExchanges: [],
          },
          request: {
            method: "GET",
            url: "https://example.com",
            headers: {},
            body: null,
          },
          response: { statusCode: 200, headers: {}, body: null },
        },
      }),
      makeJob({
        id: SignatureJobId("j3"),
        status: SignatureJobStatus.Error,
        error: "Connection refused" as any,
      }),
      makeJob({
        id: SignatureJobId("j4"),
        status: SignatureJobStatus.Completed,
        finding: {
          vulnerable: true,
          evidence: {
            judgmentId: "sql-error-pattern",
            exchanges: [],
            evidenceExchanges: [],
          },
          request: {
            method: "POST",
            url: "https://example.com/api",
            headers: {},
            body: null,
          },
          response: { statusCode: 500, headers: {}, body: null },
        },
      }),
    ];

    await commandBus.broadcast(new GenerateReportCommand({ scanState, jobs }));

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

    const plugin = new JsonReporterPlugin({ outputPath });
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const scanState = makeScanState();

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [] }),
    );

    const raw = await fs.readFile(outputPath, "utf-8");
    const report = JSON.parse(raw);

    expect(report.scanState).toEqual(serializeScanState(scanState));
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

    const plugin = new JsonReporterPlugin({ outputPath });
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
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
