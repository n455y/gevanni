import { describe, it, expect, beforeEach, afterEach } from "vitest";
import http from "node:http";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { PostmanPlugin, buildRequest } from "./postman.js";
import { ReplayCommand } from "../../commands/replay.js";
import { InterceptCommand } from "../../commands/intercept.js";
import type { HttpRequest, HttpResponse, Scenario, TamperInstruction } from "../../types/models.js";
import type { Brand } from "../../types/branded.js";

let commandBus: InMemoryCommandBus;
let server: http.Server;
let serverPort: number;

beforeEach(async () => {
  commandBus = new InMemoryCommandBus();

  // Start a local HTTP server for integration testing
  server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "text/plain", "X-Test": "ok" });
      res.end(
        JSON.stringify({
          method: req.method,
          url: req.url,
          headers: req.headers,
          body,
        }),
      );
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, () => resolve());
  });
  const addr = server.address();
  if (addr && typeof addr === "object") {
    serverPort = addr.port;
  } else {
    throw new Error("Failed to get server port");
  }
});

afterEach(() => {
  server.close();
});

function makeScenario(overrides: {
  method?: string;
  url?: string;
  headers?: Array<{ key: string; value: string }>;
  body?: string;
}): Scenario {
  const method = overrides.method ?? "GET";
  const url = overrides.url ?? `http://127.0.0.1:${serverPort}/test`;
  const headers = overrides.headers ?? [];
  const body = overrides.body;

  return {
    id: "test-scenario-1" as Brand<string, "ScenarioId">,
    name: "Test Scenario",
    type: "postman" as Brand<string, "ScenarioType">,
    source: {
      item: {
        request: {
          method,
          url: { raw: url },
          header: headers,
          ...(body !== undefined ? { body: { mode: "raw", raw: body } } : {}),
        },
      },
    },
  };
}

function makeTamperInstruction(): TamperInstruction {
  return {
    parameter: {
      type: "query" as Brand<string, "ParameterType">,
      location: { name: "q" },
      originalValue: "original",
      allowedTampers: ["replaceValue" as Brand<"replaceValue", "TamperMethod">],
    },
    payload: "<script>" as Brand<string, "Payload">,
    method: "replaceValue" as Brand<"replaceValue", "TamperMethod">,
  };
}

describe("PostmanPlugin", () => {
  it("sends request directly when no instructions are provided", async () => {
    const plugin = new PostmanPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const scenario = makeScenario({ method: "GET" });

    const result = await commandBus.dispatch<{ request: HttpRequest; response: HttpResponse }>(
      new ReplayCommand(scenario, []),
    );

    expect(result.request).toBeDefined();
    expect(result.response).toBeDefined();
    expect(result.response.statusCode).toBe(200);
    expect(result.response.headers["x-test"]).toBe("ok");

    const body = JSON.parse(
      (result.response.body as Buffer).toString("utf-8"),
    );
    expect(body.method).toBe("GET");
    expect(body.url).toBe("/test");
  });

  it("delegates to InterceptCommand when instructions are provided", async () => {
    const plugin = new PostmanPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    // Register a mock InterceptCommand handler
    let interceptedRequest: HttpRequest | null = null;
    let interceptedInstructions: TamperInstruction[] | null = null;

    commandBus.register(InterceptCommand, async (cmd: InterceptCommand) => {
      interceptedRequest = cmd.request;
      interceptedInstructions = cmd.instructions;
      // Return a mock response
      return {
        request: cmd.request,
        response: {
          statusCode: 200,
          headers: { "x-mock": "true" },
          body: Buffer.from("mocked"),
        },
      };
    });

    const scenario = makeScenario({ method: "POST" });
    const instructions = [makeTamperInstruction()];

    const result = await commandBus.dispatch<{ request: HttpRequest; response: HttpResponse }>(
      new ReplayCommand(scenario, instructions),
    );

    // Should have delegated to InterceptCommand
    expect(interceptedRequest).toBeDefined();
    expect(interceptedRequest!.method).toBe("POST");
    expect(interceptedInstructions).toHaveLength(1);
    expect(result.response.headers["x-mock"]).toBe("true");
  });

  it("sends POST request with body from scenario source", async () => {
    const plugin = new PostmanPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const scenario = makeScenario({
      method: "POST",
      body: '{"key":"value"}',
    });

    const result = await commandBus.dispatch<{ request: HttpRequest; response: HttpResponse }>(
      new ReplayCommand(scenario, []),
    );

    expect(result.response.statusCode).toBe(200);

    const body = JSON.parse(
      (result.response.body as Buffer).toString("utf-8"),
    );
    expect(body.method).toBe("POST");
    expect(body.body).toBe('{"key":"value"}');
  });
});

describe("buildRequest", () => {
  it("builds a GET request from a Postman item with url object", () => {
    const scenario: Scenario = {
      id: "s1" as Brand<string, "ScenarioId">,
      name: "Test",
      type: "postman" as Brand<string, "ScenarioType">,
      source: {
        item: {
          request: {
            method: "GET",
            url: { raw: "https://example.com/api/users" },
            header: [
              { key: "Accept", value: "application/json" },
              { key: "Authorization", value: "Bearer token123" },
            ],
          },
        },
      },
    };

    const request = buildRequest(scenario);

    expect(request.method).toBe("GET");
    expect(request.url).toBe("https://example.com/api/users");
    expect(request.headers["Accept"]).toBe("application/json");
    expect(request.headers["Authorization"]).toBe("Bearer token123");
    expect(request.body).toBeNull();
  });

  it("builds a POST request with body from a Postman item", () => {
    const scenario: Scenario = {
      id: "s2" as Brand<string, "ScenarioId">,
      name: "Test POST",
      type: "postman" as Brand<string, "ScenarioType">,
      source: {
        item: {
          request: {
            method: "POST",
            url: { raw: "https://example.com/api/submit" },
            header: [{ key: "Content-Type", value: "application/json" }],
            body: { mode: "raw", raw: '{"name":"test"}' },
          },
        },
      },
    };

    const request = buildRequest(scenario);

    expect(request.method).toBe("POST");
    expect(request.url).toBe("https://example.com/api/submit");
    expect(request.headers["Content-Type"]).toBe("application/json");
    expect(request.body).not.toBeNull();
    expect((request.body as Buffer).toString("utf-8")).toBe('{"name":"test"}');
  });

  it("handles url as a plain string", () => {
    const scenario: Scenario = {
      id: "s3" as Brand<string, "ScenarioId">,
      name: "Test String URL",
      type: "postman" as Brand<string, "ScenarioType">,
      source: {
        item: {
          request: {
            method: "GET",
            url: "https://example.com/string-url",
          },
        },
      },
    };

    const request = buildRequest(scenario);

    expect(request.url).toBe("https://example.com/string-url");
  });

  it("handles missing headers and body gracefully", () => {
    const scenario: Scenario = {
      id: "s4" as Brand<string, "ScenarioId">,
      name: "Minimal",
      type: "postman" as Brand<string, "ScenarioType">,
      source: {
        item: {
          request: {
            method: "DELETE",
            url: { raw: "https://example.com/resource/1" },
          },
        },
      },
    };

    const request = buildRequest(scenario);

    expect(request.method).toBe("DELETE");
    expect(request.url).toBe("https://example.com/resource/1");
    expect(request.headers).toEqual({});
    expect(request.body).toBeNull();
  });

  it("handles body with empty raw string", () => {
    const scenario: Scenario = {
      id: "s5" as Brand<string, "ScenarioId">,
      name: "Empty Body",
      type: "postman" as Brand<string, "ScenarioType">,
      source: {
        item: {
          request: {
            method: "PUT",
            url: { raw: "https://example.com/resource" },
            body: { mode: "raw", raw: "" },
          },
        },
      },
    };

    const request = buildRequest(scenario);

    // Empty raw string produces an empty Buffer
    expect(request.body).not.toBeNull();
    expect((request.body as Buffer).toString("utf-8")).toBe("");
  });
});
