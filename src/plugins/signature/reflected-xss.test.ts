import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { ReflectedXssPlugin } from "./reflected-xss.js";
import { CreateInspectorsCommand } from "../../commands/create-inspectors.js";
import { RunInspectionCommand } from "../../commands/run-inspection.js";
import type { InspectionParameter, HttpRequest, JsonPrimitive, Finding } from "../../types/models.js";
import { QueryParameter } from "../parameter/query.js";
import { FormParameter } from "../parameter/form.js";
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

function makeFormParam(name: string, value: string): InspectionParameter<unknown, unknown> {
  return new FormParameter({ name }, value, [ReplaceValue, AppendValue]);
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

describe("ReflectedXssPlugin", () => {
  it("creates definitions only for parameters with AppendValue tamper", async () => {
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

    const results = await commandBus.broadcast<InspectorDefinition[]>(
      new CreateInspectorsCommand(params),
    );

    expect(results).toHaveLength(1);
    const definitions = results[0];
    expect(definitions).toHaveLength(1);
    expect(definitions[0].signatureName).toBe("reflected-xss");
    expect(definitions[0].parameterIndices).toEqual([0]);
  });

  it("creates definitions for form parameters", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const params = [makeFormParam("username", "admin")];
    const results = await commandBus.broadcast<InspectorDefinition[]>(
      new CreateInspectorsCommand(params),
    );

    const definitions = results[0];
    expect(definitions).toHaveLength(1);
    expect(definitions[0].parameterIndices).toEqual([0]);
  });

  it("does not create definitions for non-matching parameter types", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const params = [makeHeaderParam("Authorization", "Bearer token")];
    const results = await commandBus.broadcast<InspectorDefinition[]>(
      new CreateInspectorsCommand(params),
    );

    const definitions = results[0];
    expect(definitions).toHaveLength(0);
  });

  it("detects reflected payload in response body", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const param = makeQueryParam("q", "search");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: Buffer.from('some response with <script>alert(1)</script> in it'),
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunInspectionCommand({
        signatureName: "reflected-xss",
        parameters: [param],
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(true);
    expect(finding.evidence).toContain("reflected in response body");
    expect(finding.request).toEqual(mockRequest);
  });

  it("does not report vulnerability when payload is not reflected", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const param = makeQueryParam("q", "search");
    const mockReplay = async () => ({
      request: mockRequest,
      response: {
        statusCode: 200,
        headers: {},
        body: Buffer.from("safe response without any script tags"),
      },
    });

    const finding: Finding = await commandBus.dispatch(
      new RunInspectionCommand({
        signatureName: "reflected-xss",
        parameters: [param],
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence).toContain("not reflected");
  });

  it("handles null response body", async () => {
    const plugin = new ReflectedXssPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const param = makeQueryParam("q", "search");
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
        signatureName: "reflected-xss",
        parameters: [param],
        replay: mockReplay,
      }),
    );

    expect(finding.vulnerable).toBe(false);
    expect(finding.evidence).toContain("not reflected");
  });
});
