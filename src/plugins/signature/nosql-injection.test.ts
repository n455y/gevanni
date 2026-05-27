import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { NosqlInjectionPlugin, NOSQL_ERROR_PATTERNS } from "./nosql-injection.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type {
  AuditParameter,
  HttpRequest,
  JsonPrimitive,
  Finding,
} from "../../types/models.ts";
import { ReplayResult, BuiltinMutationType } from "../../types/models.ts";
import { QueryParameter } from "../parameter/query.ts";
import { JsonPrimitiveParameter } from "../parameter/json.ts";
import { HeaderParameter } from "../parameter/header.ts";
import { ExchangeId, SignatureId } from "../../types/branded.ts";
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

describe("NosqlInjectionPlugin", () => {
  it("creates definitions only for parameters with AppendValue mutation", async () => {
    const plugin = new NosqlInjectionPlugin();
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
    expect(items[0].signatureName).toBe("nosql-injection");
    expect(items[0].parameter).toEqual(targets[0]);
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new NosqlInjectionPlugin();
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

  it("detects MongoDB error in response body", async () => {
    const plugin = new NosqlInjectionPlugin();
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
        body: Buffer.from("MongoError: SyntaxError: Unexpected token"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("nosql-injection"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence.judgmentId).toBe("nosql-error-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(1);
  });

  it("detects BSON error in response body", async () => {
    const plugin = new NosqlInjectionPlugin();
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
        body: Buffer.from("Invalid BSON document"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("nosql-injection"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(true);
  });

  it("detects CouchDB error in response body", async () => {
    const plugin = new NosqlInjectionPlugin();
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
        body: Buffer.from("CouchDB error: bad request"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("nosql-injection"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(true);
  });

  it("does not report vulnerability when no NoSQL error in response", async () => {
    const plugin = new NosqlInjectionPlugin();
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
        signatureName: SignatureId("nosql-injection"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence.judgmentId).toBe("nosql-error-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("handles null response body", async () => {
    const plugin = new NosqlInjectionPlugin();
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
        signatureName: SignatureId("nosql-injection"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );
    const { finding } = findings[0] as { status: "completed"; finding: Finding };

    expect(finding.vulnerable).toBe(false);
  });

  it("includes all required NoSQL error patterns", () => {
    expect(NOSQL_ERROR_PATTERNS).toHaveLength(8);
    expect(NOSQL_ERROR_PATTERNS[0].test("MongoError: SyntaxError")).toBe(true);
    expect(NOSQL_ERROR_PATTERNS[1].test("Mongo::Error::OperationFailure")).toBe(true);
    expect(NOSQL_ERROR_PATTERNS[2].test("MongoDB driver error")).toBe(true);
    expect(NOSQL_ERROR_PATTERNS[3].test("mongo exception: some error")).toBe(true);
    expect(NOSQL_ERROR_PATTERNS[4].test("CouchDB error: bad request")).toBe(true);
    expect(NOSQL_ERROR_PATTERNS[5].test("Cassandra error: invalid query")).toBe(true);
    expect(NOSQL_ERROR_PATTERNS[6].test("Invalid BSON document")).toBe(true);
    expect(NOSQL_ERROR_PATTERNS[7].test("BSONError: invalid key")).toBe(true);
  });
});
