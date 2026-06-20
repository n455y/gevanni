import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { XxeInjectionPlugin, XXE_ERROR_PATTERNS } from "./xxe-injection.ts";
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

describe("XxeInjectionPlugin", () => {
  it("creates definitions only for parameters with ReplaceValue mutation", async () => {
    const plugin = new XxeInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeQueryParameter("xml", "<foo/>"),
      makeJsonPrimitiveParam(["data", "xml"], "<bar/>"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(2);
    expect(items[0].signatureName).toBe("signature:xxe-injection");
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new XxeInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      new QueryParameter({ name: "q" }, "test", [
        BuiltinMutationType.AppendValue,
      ]),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(0);
  });

  it("detects SAXParseException in response body", async () => {
    const plugin = new XxeInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("xml", "<foo/>");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 500,
          headers: {},
          body: Buffer.from(
            'SAXParseException: The entity "xxe" was referenced, but not declared.',
          ),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:xxe-injection",
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
    expect(finding.evidence.judgmentId).toBe("xxe-error-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(1);
  });

  it("detects XML Parsing Error in response body", async () => {
    const plugin = new XxeInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("xml", "<foo/>");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 500,
          headers: {},
          body: Buffer.from("XML Parsing Error: not well-formed"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:xxe-injection",
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

  it("detects external entity restriction error in response body", async () => {
    const plugin = new XxeInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("xml", "<foo/>");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 500,
          headers: {},
          body: Buffer.from("External entity is not allowed in this context"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:xxe-injection",
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

  it("does not report vulnerability when no XXE error in response", async () => {
    const plugin = new XxeInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("xml", "<foo/>");
    const mockReplay = async () =>
      new ReplayResult({
        id: ExchangeId("test-exchange-id"),
        request: mockRequest,
        response: {
          statusCode: 200,
          headers: {},
          body: Buffer.from("<result>ok</result>"),
        },
      });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: "signature:xxe-injection",
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
    expect(finding.evidence.judgmentId).toBe("xxe-error-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("handles null response body", async () => {
    const plugin = new XxeInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("xml", "<foo/>");
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
        signatureName: "signature:xxe-injection",
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

  it("includes all required XXE error patterns", () => {
    expect(XXE_ERROR_PATTERNS).toHaveLength(12);
    expect(
      XXE_ERROR_PATTERNS[0].test("SAXParseException: not well-formed"),
    ).toBe(true);
    expect(XXE_ERROR_PATTERNS[1].test("SAXParser exception occurred")).toBe(
      true,
    );
    expect(XXE_ERROR_PATTERNS[2].test("XML parser error at line 1")).toBe(true);
    expect(XXE_ERROR_PATTERNS[3].test("XML Parsing Error: syntax error")).toBe(
      true,
    );
    expect(XXE_ERROR_PATTERNS[4].test("org.xml.sax.SAXParseException")).toBe(
      true,
    );
    expect(
      XXE_ERROR_PATTERNS[5].test(
        "javax.xml.parsers.ParserConfigurationException",
      ),
    ).toBe(true);
    expect(
      XXE_ERROR_PATTERNS[6].test(
        "System.Xml.XmlException: root element missing",
      ),
    ).toBe(true);
    expect(XXE_ERROR_PATTERNS[7].test("libxml2 error: internal error")).toBe(
      true,
    );
    expect(XXE_ERROR_PATTERNS[8].test("XML_E_INVALID_UNICODE")).toBe(true);
    expect(XXE_ERROR_PATTERNS[9].test("not well-formed xml")).toBe(true);
    expect(XXE_ERROR_PATTERNS[10].test("entity foo not defined")).toBe(true);
    expect(
      XXE_ERROR_PATTERNS[11].test(
        "External entity is not allowed in this context",
      ),
    ).toBe(true);
  });
});
