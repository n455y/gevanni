import { describe, it, expect, beforeEach, vi } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { ConsoleReporterPlugin } from "./console-reporter.js";
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

// --- Tests ---
let commandBus: InMemoryCommandBus;

beforeEach(async () => {
  commandBus = new InMemoryCommandBus();
  const plugin = new ConsoleReporterPlugin();
  await plugin.init({
    commandBus,
    eventBus: new InMemoryEventBus(),
    config: {},
  });
});

describe("ConsoleReporterPlugin", () => {
  it("prints header with scan state info", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState({
      id: asScanId("scan-abc"),
      status: asScanStatus("scanning"),
      startedAt: asIsoDateTime("2025-06-01T12:00:00Z"),
    });

    await commandBus.broadcast(new GenerateReportCommand({ scanState, jobs: [] }));

    expect(logSpy).toHaveBeenCalledOnce();
    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("=== Gevanni Scan Report ===");
    expect(output).toContain("Scan ID: scan-abc");
    expect(output).toContain("Status: scanning");
    expect(output).toContain("Started: 2025-06-01T12:00:00Z");

    logSpy.mockRestore();
  });

  it("prints vulnerable findings with details", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();
    const vulnerableJob = makeJob({
      id: asJobId("job-vuln"),
      signatureName: "reflected-xss",
      status: asJobStatus("completed"),
      parameter: new InspectionParameter({ name: "q" }, "<script>alert(1)</script>", []),
      finding: {
        vulnerable: true,
        evidence: asEvidence("XSS payload reflected in response body"),
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
    expect(output).toContain("Parameter:");
    expect(output).toContain("Evidence: XSS payload reflected in response body");
    expect(output).toContain("Request: GET https://example.com/search?q=%3Cscript%3E");

    logSpy.mockRestore();
  });

  it("prints safe findings with limited info", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();
    const safeJob = makeJob({
      id: asJobId("job-safe"),
      signatureName: "sqli-error",
      status: asJobStatus("completed"),
      finding: {
        vulnerable: false,
        evidence: asEvidence(""),
        request: { method: "POST", url: "https://example.com/login", headers: {}, body: null },
        response: { statusCode: 200, headers: {}, body: null },
      },
    });

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [safeJob] }),
    );

    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("[SAFE] sqli-error");
    expect(output).toContain("Parameter:");
    expect(output).not.toContain("Evidence:");
    expect(output).not.toContain("Request: POST");

    logSpy.mockRestore();
  });

  it("prints error findings with error message", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();
    const errorJob = makeJob({
      id: asJobId("job-err"),
      signatureName: "reflected-xss",
      status: asJobStatus("error"),
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
        id: asJobId("j1"),
        status: asJobStatus("completed"),
        finding: {
          vulnerable: true,
          evidence: asEvidence("e1"),
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
