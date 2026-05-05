import { describe, it, expect, beforeEach, afterEach } from "vitest";
import http from "node:http";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { PostmanPlugin, buildRequest, runNewman } from "./postman.js";
import { startTamperProxy } from "../proxy/http-proxy.js";
import type { TamperProxy } from "../proxy/http-proxy.js";
import { ReplayCommand, type ReplayConfig } from "../../commands/replay.js";
import { QueryTamperPlugin } from "../tamper/query-tamper.js";
import type { HttpRequest, HttpResponse, Scenario, TamperInstruction } from "../../types/models.js";
import type { Brand } from "../../types/branded.js";

let commandBus: InMemoryCommandBus;
let server: http.Server;
let serverPort: number;

beforeEach(async () => {
  commandBus = new InMemoryCommandBus();

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
  it("sends request through proxy with empty instructions", { timeout: 30_000 }, async () => {
    const plugin = new PostmanPlugin();
    const proxy = await startTamperProxy([], commandBus);

    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const scenario = makeScenario({ method: "GET" });
    const config: ReplayConfig = { instructions: [], proxyPort: proxy.port, replayId: "test-plan" };

    const result = await commandBus.dispatch<{ request: HttpRequest; response: HttpResponse }>(
      new ReplayCommand(scenario, config),
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

    proxy.close();
  });

  it("applies tamper via proxy when instructions are provided", { timeout: 30_000 }, async () => {
    const plugin = new PostmanPlugin();
    const queryTamper = new QueryTamperPlugin();
    const instructions = [makeTamperInstruction()];
    const proxy = await startTamperProxy(instructions, commandBus);

    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });
    await queryTamper.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const scenario = makeScenario({
      method: "GET",
      url: `http://127.0.0.1:${serverPort}/test?q=original`,
    });
    const config: ReplayConfig = { instructions, proxyPort: proxy.port, replayId: "test-tamper" };

    const result = await commandBus.dispatch<{ request: HttpRequest; response: HttpResponse }>(
      new ReplayCommand(scenario, config),
    );

    expect(result.response.statusCode).toBe(200);

    const body = JSON.parse(
      (result.response.body as Buffer).toString("utf-8"),
    );
    expect(body.url).toBe("/test?q=%3Cscript%3E");

    proxy.close();
  });

  it("sends POST request with body from scenario source", { timeout: 30_000 }, async () => {
    const plugin = new PostmanPlugin();
    const proxy = await startTamperProxy([], commandBus);

    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const scenario = makeScenario({
      method: "POST",
      body: '{"key":"value"}',
    });
    const config: ReplayConfig = { instructions: [], proxyPort: proxy.port, replayId: "test-post" };

    const result = await commandBus.dispatch<{ request: HttpRequest; response: HttpResponse }>(
      new ReplayCommand(scenario, config),
    );

    expect(result.response.statusCode).toBe(200);

    const body = JSON.parse(
      (result.response.body as Buffer).toString("utf-8"),
    );
    expect(body.method).toBe("POST");
    expect(body.body).toBe('{"key":"value"}');

    proxy.close();
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

    expect(request.body).not.toBeNull();
    expect((request.body as Buffer).toString("utf-8")).toBe("");
  });
});

describe("runNewman", () => {
  let runNewmanProxy: TamperProxy;

  beforeEach(async () => {
    runNewmanProxy = await startTamperProxy([], commandBus);
  });

  afterEach(() => {
    runNewmanProxy.close();
  });

  it("executes a GET request and returns the response", { timeout: 30_000 }, async () => {
    const scenario: Scenario = {
      id: "s1" as Brand<string, "ScenarioId">,
      name: "Test Newman GET",
      type: "postman" as Brand<string, "ScenarioType">,
      source: {
        item: {
          request: {
            method: "GET",
            url: { raw: `http://127.0.0.1:${serverPort}/test` },
          },
        },
      },
    };

    const response = await runNewman(scenario, runNewmanProxy.port);

    expect(response.statusCode).toBe(200);
    expect(response.headers["x-test"]).toBe("ok");

    const body = JSON.parse(
      (response.body as Buffer).toString("utf-8"),
    );
    expect(body.method).toBe("GET");
    expect(body.url).toBe("/test");
  });

  it("executes a POST request with body", { timeout: 30_000 }, async () => {
    const scenario: Scenario = {
      id: "s2" as Brand<string, "ScenarioId">,
      name: "Test Newman POST",
      type: "postman" as Brand<string, "ScenarioType">,
      source: {
        item: {
          request: {
            method: "POST",
            url: { raw: `http://127.0.0.1:${serverPort}/submit` },
            header: [{ key: "Content-Type", value: "application/json" }],
            body: { mode: "raw", raw: '{"key":"value"}' },
          },
        },
      },
    };

    const response = await runNewman(scenario, runNewmanProxy.port);

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(
      (response.body as Buffer).toString("utf-8"),
    );
    expect(body.method).toBe("POST");
    expect(body.body).toBe('{"key":"value"}');
  });
});
