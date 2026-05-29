import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { SqliErrorPlugin, SQL_ERROR_PATTERNS } from "./sqli-error.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type {
  AuditParameter,
  HttpRequest,
  JsonPrimitive,
  Finding,
  Exchange,
} from "../../types/models.ts";
import { ReplayResult, BuiltinMutationType } from "../../types/models.ts";
import { QueryParameter } from "../parameter/query.ts";
import { JsonPrimitiveParameter } from "../parameter/json.ts";
import { HeaderParameter } from "../parameter/header.ts";
import { ExchangeId, ScenarioId, SignatureId } from "../../types/branded.ts";
import type { AuditItem } from "../../core/audit-item.ts";

let commandBus: InMemoryCommandBus;
const noopLogger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

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

describe("SqliErrorPlugin", () => {
  it("creates definitions only for parameters with StandardMutationType.AppendValue tamper", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeQueryParameter("id", "1"),
      makeJsonPrimitiveParam(["user", "id"], 1),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("sqli-error");
    expect(items[0].parameter).toEqual(targets[0]);
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeJsonPrimitiveParam(["user", "id"], 1),
      makeHeaderTarget("Authorization", "Bearer token"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(0);
  });

  it("detects MySQL SQL error in response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from(
          "You have an error in your SQL syntax. MySQL server version 5.7",
        ),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-error"),
        scenarioId: ScenarioId("test-scenario"),
        parameter: parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence.judgmentId).toBe("sql-error-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(1);
  });

  it("detects PostgreSQL SQL error in response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("PostgreSQL ERROR: syntax error at or near"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-error"),
        scenarioId: ScenarioId("test-scenario"),
        parameter: parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence.judgmentId).toBe("sql-error-pattern");
  });

  it("detects Oracle SQL error in response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("ORA-01722 invalid number"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-error"),
        scenarioId: ScenarioId("test-scenario"),
        parameter: parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(true);
  });

  it("detects SQL Server error in response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from(
          "Microsoft OLE DB Provider for ODBC SQL Server error",
        ),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-error"),
        scenarioId: ScenarioId("test-scenario"),
        parameter: parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(true);
  });

  it("detects SQLite error in response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from('SQLITE_ERROR: near "OR": syntax error'),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-error"),
        scenarioId: ScenarioId("test-scenario"),
        parameter: parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(true);
  });

  it("does not report vulnerability when no SQL error in response", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: Buffer.from("normal response with no errors"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("sqli-error"),
        scenarioId: ScenarioId("test-scenario"),
        parameter: parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence.judgmentId).toBe("sql-error-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("handles null response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("id", "1");
    const mockReplay = async () => new ReplayResult({
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
        signatureName: SignatureId("sqli-error"),
        scenarioId: ScenarioId("test-scenario"),
        parameter: parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(false);
  });

  it("includes all required SQL error patterns", () => {
    expect(SQL_ERROR_PATTERNS).toHaveLength(5);
    expect(
      SQL_ERROR_PATTERNS[0].test(
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
      ),
    ).toBe(true);
    expect(SQL_ERROR_PATTERNS[1].test("PostgreSQL ERROR: syntax error")).toBe(
      true,
    );
    expect(SQL_ERROR_PATTERNS[2].test("ORA-12345")).toBe(true);
    expect(
      SQL_ERROR_PATTERNS[3].test(
        "Microsoft OLE DB Provider for ODBC SQL Server error",
      ),
    ).toBe(true);
    expect(
      SQL_ERROR_PATTERNS[4].test('SQLITE_ERROR: near "OR": syntax error'),
    ).toBe(true);
  });
});
