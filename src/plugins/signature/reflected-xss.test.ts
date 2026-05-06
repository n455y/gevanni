import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { ReflectedXssPlugin, ReflectedXssInspector } from "./reflected-xss.js";
import { CreateInspectorsCommand } from "../../commands/create-inspectors.js";
import type { InspectionParameter, HttpRequest } from "../../types/models.js";
import { ReplaceValue, AppendValue } from "../../types/branded.js";
import { QueryParameterType } from "../parser/query-parser.js";
import { FormParameterType } from "../parser/form-parser.js";
import { JsonPrimitiveParameterType } from "../parser/json-parser.js";
import { HeaderParameterType } from "../parser/header-parser.js";
import type { SignatureInspector, ReplayFn } from "../../core/inspector.js";

let commandBus: InMemoryCommandBus;

beforeEach(() => {
  commandBus = new InMemoryCommandBus();
});

function makeQueryParam(name: string, value: string): InspectionParameter {
  return {
    type: QueryParameterType,
    location: { name },
    originalValue: value,
    allowedTampers: [ReplaceValue, AppendValue],
  };
}

function makeJsonPrimitiveParam(path: string[], value: unknown): InspectionParameter {
  return {
    type: JsonPrimitiveParameterType,
    location: { path },
    originalValue: value,
    allowedTampers: [ReplaceValue],
  };
}

function makeFormParam(name: string, value: string): InspectionParameter {
  return {
    type: FormParameterType,
    location: { name },
    originalValue: value,
    allowedTampers: [ReplaceValue, AppendValue],
  };
}

function makeHeaderParam(name: string, value: string): InspectionParameter {
  return {
    type: HeaderParameterType,
    location: { name },
    originalValue: value,
    allowedTampers: [ReplaceValue],
  };
}

const mockRequest: HttpRequest = {
  method: "GET",
  url: "http://test.com",
  headers: {},
  body: null,
};

describe("ReflectedXssPlugin", () => {
  it("creates inspectors only for parameters with AppendValue tamper", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const params = [
      makeQueryParam("q", "search"),
      makeJsonPrimitiveParam(["user", "name"], "test"),
    ];

    const results = await commandBus.broadcast<SignatureInspector[]>(
      new CreateInspectorsCommand(params),
    );

    expect(results).toHaveLength(1);
    const inspectors = results[0];
    expect(inspectors).toHaveLength(1);
    expect(inspectors[0].signatureName).toBe("reflected-xss");
    expect(inspectors[0].parameters).toEqual([params[0]]);
  });

  it("creates inspectors for form parameters", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const params = [makeFormParam("username", "admin")];
    const results = await commandBus.broadcast<SignatureInspector[]>(
      new CreateInspectorsCommand(params),
    );

    const inspectors = results[0];
    expect(inspectors).toHaveLength(1);
    expect(inspectors[0].parameters).toEqual([params[0]]);
  });

  it("does not create inspectors for non-matching parameter types", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const params = [makeHeaderParam("Authorization", "Bearer token")];
    const results = await commandBus.broadcast<SignatureInspector[]>(
      new CreateInspectorsCommand(params),
    );

    const inspectors = results[0];
    expect(inspectors).toHaveLength(0);
  });

  it("detects reflected payload in response body", async () => {
    const param = makeQueryParam("q", "search");
    const inspector = new ReflectedXssInspector(param);

    const mockReplay: ReplayFn = async () => ({
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: Buffer.from('some response with <script>alert(1)</script> in it'),
      },
    });

    const finding = await inspector.inspect(mockReplay);
    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence).toContain("reflected in response body");
    expect(finding.request).toEqual(mockRequest);
  });

  it("does not report vulnerability when payload is not reflected", async () => {
    const param = makeQueryParam("q", "search");
    const inspector = new ReflectedXssInspector(param);

    const mockReplay: ReplayFn = async () => ({
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: Buffer.from("safe response without any script tags"),
      },
    });

    const finding = await inspector.inspect(mockReplay);
    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence).toContain("not reflected");
  });

  it("handles null response body", async () => {
    const param = makeQueryParam("q", "search");
    const inspector = new ReflectedXssInspector(param);

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
    expect(finding.evidence).toContain("not reflected");
  });
});
