import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import InfoDisclosurePlugin, {
  STACK_TRACE_PATTERNS,
  TECHNOLOGY_LEAK_PATTERNS,
  DEFAULT_INTERNAL_PATH_PATTERNS,
} from "./info-disclosure.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type {
  AuditParameter,
  HttpRequest,
  Finding,
  Scenario,
} from "../../types/models.ts";
import { ReplayResult, BuiltinMutationType } from "../../types/models.ts";
import { QueryParameter } from "../parameter/query/model.ts";
import {
  ExchangeId,
  ScenarioId,
  ScenarioType,
} from "../../types/branded.ts";
import type { AuditItem } from "../../core/audit-item.ts";

function makeScenario(overrides: Partial<Scenario> = {}): Scenario {
  return {
    id: ScenarioId("test-scenario"),
    name: "Test Scenario",
    type: ScenarioType("test"),
    source: null,
    representation: "Test Scenario",
    diffStrategy: { type: "exact" },
    ...overrides,
  };
}

let commandBus: InMemoryCommandBus;
const noopLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeQueryParameter(name: string, value: string): AuditParameter {
  return new QueryParameter({ name }, value, [
    BuiltinMutationType.ReplaceValue,
    BuiltinMutationType.AppendValue,
  ]);
}

const mockRequest: HttpRequest = {
  method: "GET",
  url: "http://test.com",
  headers: {},
  body: null,
};

describe("InfoDisclosurePlugin", () => {
  it("creates definitions for any parameter type (no mutation filter)", async () => {
    const plugin = new InfoDisclosurePlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeQueryParameter("q", "test"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("signature:info-disclosure");
  });

  it("detects JavaScript stack trace in response body", async () => {
    const plugin = new InfoDisclosurePlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 500,
          headers: {},
          body: Buffer.from(
            "Error: something broke\n    at processRequest (/app/server.js:42:15)\n    at handleRoute (/app/routes.js:108:3)",
          ),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:info-disclosure",
        scenario: makeScenario(),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as {
      status: "completed";
      finding: Finding;
    };

    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence.judgmentId).toBe("info-disclosure-detected");
  });

  it("detects Python traceback in response body", async () => {
    const plugin = new InfoDisclosurePlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 500,
          headers: {},
          body: Buffer.from(
            'Traceback (most recent call last):\n  File "/app/main.py", line 42, in handle\n    result = process()',
          ),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:info-disclosure",
        scenario: makeScenario(),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as {
      status: "completed";
      finding: Finding;
    };

    expect(finding.vulnerable).toBe(true);
  });

  it("detects technology version leak in headers", async () => {
    const plugin = new InfoDisclosurePlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: { "X-Powered-By": "Express", "Server": "nginx/1.18.0" },
          body: Buffer.from("ok"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:info-disclosure",
        scenario: makeScenario(),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as {
      status: "completed";
      finding: Finding;
    };

    expect(finding.vulnerable).toBe(true);
  });

  it("detects internal path disclosure", async () => {
    const plugin = new InfoDisclosurePlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from("Config loaded from /var/www/config.json"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:info-disclosure",
        scenario: makeScenario(),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as {
      status: "completed";
      finding: Finding;
    };

    expect(finding.vulnerable).toBe(true);
  });

  it("detects detailed error on 500 response", async () => {
    const plugin = new InfoDisclosurePlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 500,
          headers: {},
          body: Buffer.from("Internal Server Error: database connection failed at pg://localhost:5432"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:info-disclosure",
        scenario: makeScenario(),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as {
      status: "completed";
      finding: Finding;
    };

    expect(finding.vulnerable).toBe(true);
  });

  it("does not report vulnerability on clean response", async () => {
    const plugin = new InfoDisclosurePlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: { "Content-Type": "application/json" },
          body: Buffer.from('{"status": "ok"}'),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:info-disclosure",
        scenario: makeScenario(),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as {
      status: "completed";
      finding: Finding;
    };

    expect(finding.vulnerable).toBe(false);
  });

  it("accepts custom internal path patterns", async () => {
    const plugin = new InfoDisclosurePlugin({
      internalPathPatterns: ["/custom-app/"],
    });
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from("Error in /custom-app/config.yml"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:info-disclosure",
        scenario: makeScenario(),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as {
      status: "completed";
      finding: Finding;
    };

    expect(finding.vulnerable).toBe(true);
  });

  it("handles null response body", async () => {
    const plugin = new InfoDisclosurePlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("q", "test");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: null,
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:info-disclosure",
        scenario: makeScenario(),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as {
      status: "completed";
      finding: Finding;
    };

    expect(finding.vulnerable).toBe(false);
  });

  it("exports required patterns and defaults", () => {
    expect(STACK_TRACE_PATTERNS.length).toBeGreaterThan(0);
    expect(TECHNOLOGY_LEAK_PATTERNS.length).toBeGreaterThan(0);
    expect(DEFAULT_INTERNAL_PATH_PATTERNS.length).toBeGreaterThan(0);
    expect(DEFAULT_INTERNAL_PATH_PATTERNS).toContain("node_modules");
  });
});
