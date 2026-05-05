import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { SqliErrorPlugin, SqliErrorInspector, SQL_ERROR_PATTERNS } from "./sqli-error.js";
import { CreateInspectorsCommand } from "../../commands/create-inspectors.js";
import type { InspectionParameter, HttpRequest, HttpResponse } from "../../types/models.js";
import type { Brand, TamperMethod } from "../../types/branded.js";
import type { SignatureInspector, ReplayFn } from "../../core/inspector.js";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeQueryParam(name: string, value: string): InspectionParameter {
  return {
    type: "query" as Brand<"query", "ParameterType">,
    location: { name },
    originalValue: value,
    allowedTampers: ["replaceValue" as TamperMethod, "appendValue" as TamperMethod],
  };
}

function makeJsonPrimitiveParam(path: string[], value: unknown): InspectionParameter {
  return {
    type: "jsonPrimitive" as Brand<"jsonPrimitive", "ParameterType">,
    location: { path },
    originalValue: value,
    allowedTampers: ["replaceValue" as TamperMethod],
  };
}

function makeFormParam(name: string, value: string): InspectionParameter {
  return {
    type: "form" as Brand<"form", "ParameterType">,
    location: { name },
    originalValue: value,
    allowedTampers: ["replaceValue" as TamperMethod, "appendValue" as TamperMethod],
  };
}

function makeHeaderParam(name: string, value: string): InspectionParameter {
  return {
    type: "header" as Brand<"header", "ParameterType">,
    location: { name },
    originalValue: value,
    allowedTampers: ["replaceValue" as TamperMethod],
  };
}

const mockRequest: HttpRequest = {
  method: "GET",
  url: "http://test.com",
  headers: {},
  body: null,
};

describe("SqliErrorPlugin", () => {
  it("creates inspectors for query and jsonPrimitive parameters", async () => {
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

    const results = await commandBus.broadcast<SignatureInspector[]>(
      new CreateInspectorsCommand(params),
    );

    expect(results).toHaveLength(1);
    const inspectors = results[0];
    expect(inspectors).toHaveLength(2);
    expect(inspectors[0].signatureName).toBe("sqli-error");
    expect(inspectors[0].parameters).toEqual([params[0]]);
    expect(inspectors[1].signatureName).toBe("sqli-error");
    expect(inspectors[1].parameters).toEqual([params[1]]);
  });

  it("does not create inspectors for non-matching parameter types", async () => {
    const plugin = new SqliErrorPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const params = [
      makeFormParam("username", "admin"),
      makeHeaderParam("Authorization", "Bearer token"),
    ];

    const results = await commandBus.broadcast<SignatureInspector[]>(
      new CreateInspectorsCommand(params),
    );

    const inspectors = results[0];
    expect(inspectors).toHaveLength(0);
  });

  it("detects MySQL SQL error in response body", async () => {
    const param = makeQueryParam("id", "1");
    const inspector = new SqliErrorInspector(param);

    const mockReplay: ReplayFn = async () => ({
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("You have an error in your SQL syntax. MySQL server version 5.7"),
      },
    });

    const finding = await inspector.inspect(mockReplay);
    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence).toContain("SQL error pattern detected");
  });

  it("detects PostgreSQL SQL error in response body", async () => {
    const param = makeQueryParam("id", "1");
    const inspector = new SqliErrorInspector(param);

    const mockReplay: ReplayFn = async () => ({
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("PostgreSQL ERROR: syntax error at or near"),
      },
    });

    const finding = await inspector.inspect(mockReplay);
    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence).toContain("SQL error pattern detected");
  });

  it("detects Oracle SQL error in response body", async () => {
    const param = makeQueryParam("id", "1");
    const inspector = new SqliErrorInspector(param);

    const mockReplay: ReplayFn = async () => ({
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("ORA-01722 invalid number"),
      },
    });

    const finding = await inspector.inspect(mockReplay);
    expect(finding.vulnerable).toBe(true);
  });

  it("detects SQL Server error in response body", async () => {
    const param = makeQueryParam("id", "1");
    const inspector = new SqliErrorInspector(param);

    const mockReplay: ReplayFn = async () => ({
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("Microsoft OLE DB Provider for ODBC SQL Server error"),
      },
    });

    const finding = await inspector.inspect(mockReplay);
    expect(finding.vulnerable).toBe(true);
  });

  it("detects SQLite error in response body", async () => {
    const param = makeQueryParam("id", "1");
    const inspector = new SqliErrorInspector(param);

    const mockReplay: ReplayFn = async () => ({
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("SQLITE_ERROR: near \"OR\": syntax error"),
      },
    });

    const finding = await inspector.inspect(mockReplay);
    expect(finding.vulnerable).toBe(true);
  });

  it("does not report vulnerability when no SQL error in response", async () => {
    const param = makeQueryParam("id", "1");
    const inspector = new SqliErrorInspector(param);

    const mockReplay: ReplayFn = async () => ({
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: Buffer.from("normal response with no errors"),
      },
    });

    const finding = await inspector.inspect(mockReplay);
    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence).toContain("No SQL error pattern detected");
  });

  it("handles null response body", async () => {
    const param = makeQueryParam("id", "1");
    const inspector = new SqliErrorInspector(param);

    const mockReplay: ReplayFn = async () => ({
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: null,
      },
    });

    const finding = await inspector.inspect(mockReplay);
    expect(finding.vulnerable).toBe(false);
  });

  it("includes all required SQL error patterns", () => {
    expect(SQL_ERROR_PATTERNS).toHaveLength(5);
    expect(SQL_ERROR_PATTERNS[0].test("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")).toBe(true);
    expect(SQL_ERROR_PATTERNS[1].test("PostgreSQL ERROR: syntax error")).toBe(true);
    expect(SQL_ERROR_PATTERNS[2].test("ORA-12345")).toBe(true);
    expect(SQL_ERROR_PATTERNS[3].test("Microsoft OLE DB Provider for ODBC SQL Server error")).toBe(true);
    expect(SQL_ERROR_PATTERNS[4].test("SQLITE_ERROR: near \"OR\": syntax error")).toBe(true);
  });
});
