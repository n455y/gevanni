import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import {
  PathTraversalPlugin,
  PATH_TRAVERSAL_PATTERNS,
} from "./path-traversal.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type {
  AuditParameter,
  HttpRequest,
  JsonPrimitive,
  Finding,
  Scenario,
} from "../../types/models.ts";
import { ReplayResult, BuiltinMutationType } from "../../types/models.ts";
import { QueryParameter } from "../parameter/query.ts";
import { JsonPrimitiveParameter } from "../parameter/json.ts";
import { HeaderParameter } from "../parameter/header.ts";
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
    diffStrategy: "exact",
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

function makeJsonPrimitiveParam(
  path: string[],
  value: unknown,
): AuditParameter {
  return new JsonPrimitiveParameter({ path }, value as JsonPrimitive, [
    BuiltinMutationType.ReplaceValue,
  ]);
}

function makeHeaderTarget(name: string, value: string): AuditParameter {
  return new HeaderParameter({ name }, value, [
    BuiltinMutationType.ReplaceValue,
  ]);
}

const mockRequest: HttpRequest = {
  method: "GET",
  url: "http://test.com",
  headers: {},
  body: null,
};

describe("PathTraversalPlugin", () => {
  it("creates definitions only for parameters with ReplaceValue mutation", async () => {
    const plugin = new PathTraversalPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeQueryParameter("file", "report.pdf"),
      makeJsonPrimitiveParam(["path"], "/files/doc.txt"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(2);
    expect(items[0].signatureName).toBe("signature:path-traversal");
  });

  it("does not create definitions for parameters without ReplaceValue mutation", async () => {
    const plugin = new PathTraversalPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [makeHeaderTarget("Authorization", "Bearer token")];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("signature:path-traversal");
  });

  it("detects /etc/passwd content in response body", async () => {
    const plugin = new PathTraversalPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("file", "report.pdf");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
          ),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:path-traversal",
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
    expect(finding.evidence.judgmentId).toBe("file-content-disclosure");
    expect(finding.evidence.evidenceExchanges).toHaveLength(1);
  });

  it("detects win.ini content in response body", async () => {
    const plugin = new PathTraversalPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("file", "report.pdf");
    let callCount = 0;
    const mockReplay = async () => {
      callCount++;
      if (callCount === 1) {
        return new ReplayResult({
          id: ExchangeId("test-exchange-id-1"),
          request: mockRequest,
          response: {
            statusCode: 200,
            headers: {},
            body: Buffer.from("not found"),
          },
        });
      }
      return new ReplayResult({
        id: ExchangeId("test-exchange-id-2"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from(
            "[extensions]\r\n; for 16-bit app support\r\n[mci extensions]\r\n",
          ),
        },
      });
    };

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:path-traversal",
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
    expect(callCount).toBe(2);
  });

  it("does not report vulnerability when no file content in response", async () => {
    const plugin = new PathTraversalPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("file", "report.pdf");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from("file not found"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:path-traversal",
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
    expect(finding.evidence.judgmentId).toBe("file-content-disclosure");
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("handles null response body", async () => {
    const plugin = new PathTraversalPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("file", "report.pdf");
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
        signatureName: "signature:path-traversal",
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

  it("stops testing payloads after first match", async () => {
    const plugin = new PathTraversalPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("file", "report.pdf");
    let callCount = 0;
    const mockReplay = async () => {
      callCount++;
      return new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from("root:x:0:0:root:/root:/bin/bash"),
        },
      });
    };

    await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:path-traversal",
        scenario: makeScenario(),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );

    expect(callCount).toBe(1);
  });

  it("includes all required path traversal patterns", () => {
    expect(PATH_TRAVERSAL_PATTERNS).toHaveLength(3);
    expect(
      PATH_TRAVERSAL_PATTERNS[0].test("root:x:0:0:root:/root:/bin/bash"),
    ).toBe(true);
    expect(PATH_TRAVERSAL_PATTERNS[1].test("[extensions]\r\nmauto=1")).toBe(
      true,
    );
    expect(PATH_TRAVERSAL_PATTERNS[2].test("; for 16-bit app support")).toBe(
      true,
    );
  });
});
