import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.ts";
import { InMemoryEventBus } from "../../core/event-bus.ts";
import { LdapInjectionPlugin, LDAP_ERROR_PATTERNS } from "./ldap-injection.ts";
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

describe("LdapInjectionPlugin", () => {
  it("creates definitions only for parameters with AppendValue mutation", async () => {
    const plugin = new LdapInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeQueryParameter("user", "admin"),
      makeJsonPrimitiveParam(["filter"], "cn=test"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    expect(results).toHaveLength(1);
    const items = results[0];
    expect(items).toHaveLength(1);
    expect(items[0].signatureName).toBe("ldap-injection");
    expect(items[0].parameter).toEqual(targets[0]);
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new LdapInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const targets = [
      makeJsonPrimitiveParam(["filter"], "cn=test"),
      makeHeaderTarget("Authorization", "Bearer token"),
    ];

    const results = await commandBus.broadcast<AuditItem[]>(
      new CreateAuditItemsCommand(targets),
    );

    const items = results[0];
    expect(items).toHaveLength(0);
  });

  it("detects ldap_search error in response body", async () => {
    const plugin = new LdapInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("user", "admin");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("Warning: ldap_search(): Search: Operations error"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("ldap-injection"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );

    const { finding } = findings[0] as { status: "completed"; finding: Finding };
    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence.judgmentId).toBe("ldap-error-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(1);
  });

  it("detects LDAP error in response body", async () => {
    const plugin = new LdapInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("user", "admin");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("LDAP error: Invalid DN syntax"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("ldap-injection"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );

    const { finding } = findings[0] as { status: "completed"; finding: Finding };
    expect(finding.vulnerable).toBe(true);
  });

  it("detects Invalid DN error in response body", async () => {
    const plugin = new LdapInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("user", "admin");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("Invalid DN: malformed address"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("ldap-injection"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );

    const { finding } = findings[0] as { status: "completed"; finding: Finding };
    expect(finding.vulnerable).toBe(true);
  });

  it("detects No such object error in response body", async () => {
    const plugin = new LdapInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("user", "admin");
    const mockReplay = async () => new ReplayResult({
      id: ExchangeId("test-exchange-id"),
      request: mockRequest,
      response: {
        statusCode: 500,
        headers: {},
        body: Buffer.from("No such object: uid=user,ou=users,dc=example,dc=com"),
      },
    });

    const findings = await commandBus.broadcast(
      new RunAuditCommand({
        signatureName: SignatureId("ldap-injection"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );

    const { finding } = findings[0] as { status: "completed"; finding: Finding };
    expect(finding.vulnerable).toBe(true);
  });

  it("does not report vulnerability when no LDAP error in response", async () => {
    const plugin = new LdapInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("user", "admin");
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
        signatureName: SignatureId("ldap-injection"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );

    const { finding } = findings[0] as { status: "completed"; finding: Finding };
    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence.judgmentId).toBe("ldap-error-pattern");
    expect(finding.evidence.evidenceExchanges).toHaveLength(0);
  });

  it("handles null response body", async () => {
    const plugin = new LdapInjectionPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      logger: noopLogger,
    });

    const parameter = makeQueryParameter("user", "admin");
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
        signatureName: SignatureId("ldap-injection"),
        parameter,
        replay: mockReplay,
        completedJobs: [],
      }),
    );

    const { finding } = findings[0] as { status: "completed"; finding: Finding };
    expect(finding.vulnerable).toBe(false);
  });

  it("includes all required LDAP error patterns", () => {
    expect(LDAP_ERROR_PATTERNS).toHaveLength(5);
    expect(
      LDAP_ERROR_PATTERNS[0].test("Warning: ldap_search(): Search: Operations error"),
    ).toBe(true);
    expect(
      LDAP_ERROR_PATTERNS[1].test("LDAP error: Invalid DN syntax"),
    ).toBe(true);
    expect(
      LDAP_ERROR_PATTERNS[2].test("Invalid DN: malformed address"),
    ).toBe(true);
    expect(
      LDAP_ERROR_PATTERNS[3].test("No such object: uid=user,ou=users"),
    ).toBe(true);
    expect(
      LDAP_ERROR_PATTERNS[4].test("Protocol error: LDAP message"),
    ).toBe(true);
  });
});
