import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { SqliErrorPlugin, SQL_ERROR_PATTERNS } from "./sqli-error.js";
import { CreateInspectorsCommand } from "../../commands/create-inspectors.js";
import { RunInspectionCommand } from "../../commands/run-inspection.js";
import type { InspectionParameter, HttpRequest, JsonPrimitive, Finding } from "../../types/models.js";
import { QueryParameter } from "../parameter/query.js";
import { JsonPrimitiveParameter } from "../parameter/json.js";
import { HeaderParameter } from "../parameter/header.js";
import { ReplaceValue, AppendValue } from "../../types/branded.js";
import type { InspectorDefinition } from "../../core/inspector.js";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeQueryParam(name: string, value: string): InspectionParameter<unknown, unknown> {
  return new QueryParameter({ name }, value, [ReplaceValue, AppendValue]);
}

function makeJsonPrimitiveParam(path: string[], value: unknown): InspectionParameter<unknown, unknown> {
  return new JsonPrimitiveParameter({ path }, value as JsonPrimitive, [ReplaceValue]);
}

function makeHeaderParam(name: string, value: string): InspectionParameter<unknown, unknown> {
  return new HeaderParameter({ name }, value, [ReplaceValue]);
}

const mockRequest: HttpRequest = {
  method: "GET",
  url: "http://test.com",
  headers: {},
  body: null,
};

describe("SqliErrorPlugin", () => {
  it("creates definitions only for parameters with AppendValue tamper", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const params = [
      makeQueryParam("id", "1"),
      makeJsonPrimitiveParam(["user", "id"], 1),
    ];

    const results = await commandBus.broadcast<InspectorDefinition[]>(
      new CreateInspectorsCommand(params),
    );

    expect(results).toHaveLength(1);
    const definitions = results[0];
    expect(definitions).toHaveLength(1);
    expect(definitions[0].signatureName).toBe("sqli-error");
    expect(definitions[0].parameterIndices).toEqual([0]);
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const params = [
      makeJsonPrimitiveParam(["user", "id"], 1),
      makeHeaderParam("Authorization", "Bearer token"),
    ];

    const results = await commandBus.broadcast<InspectorDefinition[]>(
      new CreateInspectorsCommand(params),
    );

    const definitions = results[0];
    expect(definitions).toHaveLength(0);
  });

  it("detects MySQL SQL error in response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const param = makeQueryParam("id", "1");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("You have an error in your SQL syntax. MySQL server version 5.7"),
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunInspectionCommand({
        signatureName: "sqli-error",
        parameters: [param],
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence).toContain("SQL error pattern detected");
  });

  it("detects PostgreSQL SQL error in response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const param = makeQueryParam("id", "1");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("PostgreSQL ERROR: syntax error at or near"),
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunInspectionCommand({
        signatureName: "sqli-error",
        parameters: [param],
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence).toContain("SQL error pattern detected");
  });

  it("detects Oracle SQL error in response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const param = makeQueryParam("id", "1");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("ORA-01722 invalid number"),
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunInspectionCommand({
        signatureName: "sqli-error",
        parameters: [param],
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(true);
  });

  it("detects SQL Server error in response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const param = makeQueryParam("id", "1");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("Microsoft OLE DB Provider for ODBC SQL Server error"),
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunInspectionCommand({
        signatureName: "sqli-error",
        parameters: [param],
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(true);
  });

  it("detects SQLite error in response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const param = makeQueryParam("id", "1");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from('SQLITE_ERROR: near "OR": syntax error'),
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunInspectionCommand({
        signatureName: "sqli-error",
        parameters: [param],
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(true);
  });

  it("does not report vulnerability when no SQL error in response", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const param = makeQueryParam("id", "1");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: Buffer.from("normal response with no errors"),
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunInspectionCommand({
        signatureName: "sqli-error",
        parameters: [param],
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence).toContain("No SQL error pattern detected");
  });

  it("handles null response body", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const param = makeQueryParam("id", "1");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: null,
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunInspectionCommand({
        signatureName: "sqli-error",
        parameters: [param],
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(false);
  });

  it("includes all required SQL error patterns", () => {
    expect(SQL_ERROR_PATTERNS).toHaveLength(5);
    expect(SQL_ERROR_PATTERNS[0].test("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")).toBe(true);
    expect(SQL_ERROR_PATTERNS[1].test("PostgreSQL ERROR: syntax error")).toBe(true);
    expect(SQL_ERROR_PATTERNS[2].test("ORA-12345")).toBe(true);
    expect(SQL_ERROR_PATTERNS[3].test("Microsoft OLE DB Provider for ODBC SQL Server error")).toBe(true);
    expect(SQL_ERROR_PATTERNS[4].test('SQLITE_ERROR: near "OR": syntax error')).toBe(true);
  });
});
