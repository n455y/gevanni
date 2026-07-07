import { describe, it, expect, beforeEach, vi } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import ConsoleReporterPlugin from "./console-reporter.ts";
import { GenerateReportCommand } from "../../commands/report.ts";
import {
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

// --- Tests ---
let commandBus: InMemoryCommandBus;
const noopLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

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

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [] }),
    );

    expect(logSpy).toHaveBeenCalledOnce();
    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("=== Gevanni Scan Report ===");
    expect(output).toContain("Scan ID: scan-abc");
    expect(output).toContain("Status: scanning");
    expect(output).toContain("Started: 2025-06-01T12:00:00.000Z");

    logSpy.mockRestore();
  });

  it("prints vulnerable findings with full details", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();
    const vulnerableJob = makeJob({
      id: SignatureJobId("job-vuln"),
      signatureName: "signature:reflected-xss",
      status: SignatureJobStatus.Completed,
      groups: [],
      parameter: new QueryParameter(
        { name: "q" },
        "<script>alert(1)</script>",
        [],
      ),
      finding: {
        vulnerable: true,
        evidence: {
          judgmentId: "payload-reflection",
          exchanges: [
            {
              id: ExchangeId("ex-0"),
              request: {
                method: "GET",
                url: "https://example.com/search?q=%3Cscript%3E",
                headers: {},
                body: null,
              },
              response: { statusCode: 200, headers: {}, body: null },
            },
          ],
          evidenceExchanges: [
            {
              id: ExchangeId("ex-0"),
              request: {
                method: "GET",
                url: "https://example.com/search?q=%3Cscript%3E",
                headers: {},
                body: null,
              },
              response: {
                statusCode: 200,
                headers: {
                  "x-powered-by": "Express",
                },
                body: Buffer.from("<html><script>alert(1)</script></html>"),
              },
            },
          ],
        },
        request: {
          method: "GET",
          url: "https://example.com/search?q=%3Cscript%3E",
          headers: {},
          body: null,
        },
        response: {
          statusCode: 200,
          headers: {
            "x-powered-by": "Express",
          },
          body: Buffer.from("<html><script>alert(1)</script></html>"),
        },
      },
    });

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [vulnerableJob] }),
    );

    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("[VULNERABLE] signature:reflected-xss");
    expect(output).toContain("Group:");
    expect(output).toContain("Target:");
    expect(output).toContain("Judgment: payload-reflection (1 evidence");
    expect(output).toContain("Request: GET https://example.com/search?q=%3Cscript%3E");
    expect(output).toContain("Response Status: 200");
    expect(output).toContain("x-powered-by: Express");
    expect(output).toContain("<script>alert(1)</script>");
    expect(output).toContain("Evidence #1:");

    logSpy.mockRestore();
  });

  it("prints safe findings with limited info", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();
    const safeJob = makeJob({
      id: SignatureJobId("job-safe"),
      signatureName: "signature:sqli-error",
      status: SignatureJobStatus.Completed,
      finding: {
        vulnerable: false,
        evidence: {
          judgmentId: "sql-error-pattern",
          exchanges: [],
          evidenceExchanges: [],
        },
        request: {
          method: "POST",
          url: "https://example.com/login",
          headers: {},
          body: null,
        },
        response: { statusCode: 200, headers: {}, body: null },
      },
    });

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [safeJob] }),
    );

    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("[SAFE] signature:sqli-error");
    expect(output).toContain("Target:");
    // Safe jobs should not show judgment or response details
    expect(output).not.toContain("Judgment:");
    expect(output).not.toContain("Response Status:");
    expect(output).not.toContain("Evidence #");

    logSpy.mockRestore();
  });

  it("prints error findings with error message", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();
    const errorJob = makeJob({
      id: SignatureJobId("job-err"),
      signatureName: "signature:reflected-xss",
      status: SignatureJobStatus.Error,
      finding: null,
      error: "Connection refused" as any,
    });

    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs: [errorJob] }),
    );

    const output = logSpy.mock.calls[0][0] as string;

    expect(output).toContain("[ERROR] signature:reflected-xss");
    expect(output).toContain("Error: Connection refused");

    logSpy.mockRestore();
  });

  it("prints summary with correct counts", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

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
        error: "timeout" as any,
      }),
    ];

    await commandBus.broadcast(new GenerateReportCommand({ scanState, jobs }));

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

describe("ConsoleReporterPlugin.generate()", () => {
  it("generates report when called directly via generate()", async () => {
    const plugin = new ConsoleReporterPlugin();
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState({
      id: ScanId("scan-direct"),
      status: ScanStatus.Completed,
    });

    const vulnerableJob = makeJob({
      id: SignatureJobId("job-vuln"),
      signatureName: "signature:reflected-xss",
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
          url: "https://example.com/search",
          headers: {},
          body: null,
        },
        response: { statusCode: 200, headers: {}, body: null },
      },
    });

    await plugin.generate!(scanState, [vulnerableJob], "ignored-option");

    const output = logSpy.mock.calls[0][0] as string;
    expect(output).toContain("=== Gevanni Scan Report ===");
    expect(output).toContain("[VULNERABLE] signature:reflected-xss");
    expect(output).toContain("Response Status: 200");

    logSpy.mockRestore();
  });

  it("ignores options parameter", async () => {
    const plugin = new ConsoleReporterPlugin();
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const scanState = makeScanState();

    await plugin.generate!(scanState, [], "any-option-value");

    expect(logSpy).toHaveBeenCalledOnce();
    logSpy.mockRestore();
  });
});
