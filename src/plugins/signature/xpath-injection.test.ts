import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import {
  XpathInjectionPlugin,
  XPATH_ERROR_PATTERNS,
} from "./xpath-injection.ts";
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

describe("XpathInjectionPlugin", () => {
  it("creates definitions only for parameters with AppendValue mutation", async () => {
    const plugin = new XpathInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeQueryParameter("user", "admin"),
      makeJsonPrimitiveParam(["xpath"], "//user"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("signature:xpath-injection");
    expect(items[0].parameter).toEqual(targets[0]);
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new XpathInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeJsonPrimitiveParam(["xpath"], "//user"),
      makeHeaderTarget("Authorization", "Bearer token"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(0);
  });

  it("detects XPath error in response body", async () => {
    const plugin = new XpathInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("user", "admin");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 500,
          headers: {},
          body: Buffer.from("XPath error: Invalid predicate"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:xpath-injection",
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
    expect(finding.evidence.judgmentId).toBe("xpath-error-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(1);
  });

  it("detects Invalid expression error in response body", async () => {
    const plugin = new XpathInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("user", "admin");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 500,
          headers: {},
          body: Buffer.from("Invalid expression: unexpected token"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:xpath-injection",
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

  it("detects XPathException in response body", async () => {
    const plugin = new XpathInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("user", "admin");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 500,
          headers: {},
          body: Buffer.from(
            "javax.xml.xpath.XPathException: Error evaluating expression",
          ),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:xpath-injection",
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

  it("does not report vulnerability when no XPath error in response", async () => {
    const plugin = new XpathInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("user", "admin");
    const mockReplay = async () =>
      new ReplayResult({
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
        signatureName: "signature:xpath-injection",
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
    expect(finding.evidence.judgmentId).toBe("xpath-error-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("handles null response body", async () => {
    const plugin = new XpathInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("user", "admin");
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
        signatureName: "signature:xpath-injection",
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

  it("includes all required XPath error patterns", () => {
    expect(XPATH_ERROR_PATTERNS).toHaveLength(6);
    expect(XPATH_ERROR_PATTERNS[0].test("XPath error: Invalid predicate")).toBe(
      true,
    );
    expect(
      XPATH_ERROR_PATTERNS[1].test("Invalid expression: unexpected token"),
    ).toBe(true);
    expect(
      XPATH_ERROR_PATTERNS[2].test("Failed to compile() XPath expression"),
    ).toBe(true);
    expect(
      XPATH_ERROR_PATTERNS[3].test("net.sf.saxon.s9api.XPathException"),
    ).toBe(true);
    expect(
      XPATH_ERROR_PATTERNS[4].test("javax.xml.xpath.XPathExpressionException"),
    ).toBe(true);
    expect(
      XPATH_ERROR_PATTERNS[5].test("System.Xml.XPath.XPathException"),
    ).toBe(true);
  });
});
