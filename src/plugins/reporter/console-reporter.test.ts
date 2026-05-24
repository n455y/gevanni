import { describe, it, expect, beforeEach, vi } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { ConsoleReporterPlugin } from "./console-reporter.ts";
import { GenerateReportCommand } from "../../commands/report.ts";
import { type Job, type ScanState, JobStatus, ScanStatus } from "../../types/models.ts";
import { QueryParameter } from "../parameter/query.ts";
import {
  ScanId,
  JobId,
  ScenarioId,
  ExchangeId,
  SignatureId,
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

function makeJob(overrides: Partial<Job> = {}): Job {
  return {
    id: JobId("job-1"),
    scanId: ScanId("test-scan-id"),
    scenarioId: ScenarioId("scan-1"),
    signatureName: SignatureId("reflected-xss"),
parameter: new QueryParameter({ name: "" }, "", []),
    status: JobStatus.Completed,
    finding: null,
    error: null,
    createdAt: new Date("2025-01-01T00:00:00Z"),
    updatedAt: new Date("2025-01-01T00:00:00Z"),
    ...overrides,
  };
}

// --- Tests ---
let commandBus: InMemoryCommandBus;
const noopLogger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

beforeEach(async () => {
  commandBus = new InMemoryCommandBus();
  const plugin = new ConsoleReporterPlugin();
  await plugin.init({
    commandBus,
    eventBus: new InMemoryEventBus(),
    logger: noopLogger,
  });
});

describe("ConsoleReporterPlugin", () => {
  it("prints header with scan state info", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState({
      id: ScanId("scan-abc"),
      status: ScanStatus.Scanning,
      startedAt: new Date("2025-06-01T12:00:00Z"),
    });

    await commandBus.broadcast(new GenerateReportCommand({ scanState, jobs: [] }));

    expect(logSpy).toHaveBeenCalledOnce();
    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("=== Gevanni Scan Report ===");
    expect(output).toContain("Scan ID: scan-abc");
    expect(output).toContain("Status: scanning");
    expect(output).toContain("Started: 2025-06-01T12:00:00.000Z");

    logSpy.mockRestore();
  });

  it("prints vulnerable findings with details", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();
    const vulnerableJob = makeJob({
      id: JobId("job-vuln"),
      signatureName: SignatureId("reflected-xss"),
      status: JobStatus.Completed,
parameter: new QueryParameter({ name: "q" }, "<script>alert(1)</script>", []),
      finding: {
        vulnerable: true,
        evidence: {
          judgmentId: "payload-reflection",
          exchanges: [{ id: ExchangeId("ex-0"), request: { method: "GET", url: "https://example.com/search?q=%3Cscript%3E", headers: {}, body: null }, response: { statusCode: 200, headers: {}, body: null } }],
          evidenceExchanges: [{ id: ExchangeId("ex-0"), request: { method: "GET", url: "https://example.com/search?q=%3Cscript%3E", headers: {}, body: null }, response: { statusCode: 200, headers: {}, body: null } }],
        },
        request: {
          method: "GET",
          url: "https://example.com/search?q=%3Cscript%3E",
          headers: {},
          body: null,
        },
        response: {
          statusCode: 200,
          headers: {},
          body: null,
        },
      },
    });

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [vulnerableJob] }),
    );

    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("[VULNERABLE] reflected-xss");
    expect(output).toContain("Target:");
    expect(output).toContain("Evidence: payload-reflection (1 evidence exchanges)");
    expect(output).toContain("Request: GET https://example.com/search?q=%3Cscript%3E");

    logSpy.mockRestore();
  });

  it("prints safe findings with limited info", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();
    const safeJob = makeJob({
      id: JobId("job-safe"),
      signatureName: SignatureId("sqli-error"),
      status: JobStatus.Completed,
      finding: {
        vulnerable: false,
        evidence: { judgmentId: "sql-error-pattern", exchanges: [], evidenceExchanges: [] },
        request: { method: "POST", url: "https://example.com/login", headers: {}, body: null },
        response: { statusCode: 200, headers: {}, body: null },
      },
    });

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [safeJob] }),
    );

    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("[SAFE] sqli-error");
    expect(output).toContain("Target:");
    expect(output).not.toContain("Evidence:");
    expect(output).not.toContain("Request: POST");

    logSpy.mockRestore();
  });

  it("prints error findings with error message", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();
    const errorJob = makeJob({
      id: JobId("job-err"),
      signatureName: SignatureId("reflected-xss"),
      status: JobStatus.Error,
      finding: null,
      error: "Connection refused" as any,
    });

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [errorJob] }),
    );

    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("[ERROR] reflected-xss");
    expect(output).toContain("Error: Connection refused");

    logSpy.mockRestore();
  });

  it("prints summary with correct counts", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();
    const jobs: Job[] = [
      makeJob({
        id: JobId("j1"),
        status: JobStatus.Completed,
        finding: {
          vulnerable: true,
          evidence: { judgmentId: "payload-reflection", exchanges: [], evidenceExchanges: [] },
          request: { method: "GET", url: "https://example.com", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        },
      }),
      makeJob({
        id: JobId("j2"),
        status: JobStatus.Completed,
        finding: {
          vulnerable: false,
          evidence: { judgmentId: "sql-error-pattern", exchanges: [], evidenceExchanges: [] },
          request: { method: "GET", url: "https://example.com", headers: {}, body: null },
          response: { statusCode: 200, headers: {}, body: null },
        },
      }),
      makeJob({
        id: JobId("j3"),
        status: JobStatus.Error,
        error: "timeout" as any,
      }),
    ];

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs }),
    );

    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("--- Summary ---");
    expect(output).toContain("Total jobs: 3");
    expect(output).toContain("Vulnerable: 1");
    expect(output).toContain("Safe: 1");
    expect(output).toContain("Errors: 1");

    logSpy.mockRestore();
  });

  it("handles empty jobs list", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [] }),
    );

    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("--- Findings ---");
    expect(output).toContain("--- Summary ---");
    expect(output).toContain("Total jobs: 0");
    expect(output).toContain("Vulnerable: 0");
    expect(output).toContain("Safe: 0");
    expect(output).toContain("Errors: 0");

    logSpy.mockRestore();
  });
});
