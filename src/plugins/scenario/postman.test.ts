import { describe, it, expect, beforeEach, afterEach } from "vitest";
import http from "node:http";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { PostmanPlugin, PostmanScenarioType, runNewman } from "./postman.js";
import { startTamperProxy } from "../proxy/http-proxy.js";
import type { TamperProxy } from "../proxy/http-proxy.js";
import { ReplayCommand, type ReplayConfig } from "../../commands/replay.js";
import { LoadExchangesCommand, SaveExchangeCommand } from "../../commands/exchange.js";
import { QueryTamperPlugin } from "../parameter/query.js";
import type { Scenario, TamperInstruction, Exchange } from "../../types/models.js";
import { QueryParameter } from "../../types/models.js";
import type { Brand } from "../../types/branded.js";
import { ReplaceValue } from "../../types/branded.js";

let commandBus: InMemoryCommandBus;
let server: http.Server;
let serverPort: number;
let exchangeStore: Map<string, Exchange[]>;

beforeEach(async () => {
  commandBus = new InMemoryCommandBus();
  exchangeStore = new Map();

  commandBus.register(SaveExchangeCommand, async (cmd: SaveExchangeCommand) => {
    const list = exchangeStore.get(cmd.replayId) ?? [];
    list.push(cmd.exchange);
    exchangeStore.set(cmd.replayId, list);
  });

  commandBus.register(LoadExchangesCommand, async (cmd: LoadExchangesCommand) => {
    return exchangeStore.get(cmd.replayId) ?? [];
  });

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
    type: PostmanScenarioType,
    source: {
      items: [
        {
          request: {
            method,
            url: { raw: url },
            header: headers,
            ...(body !== undefined ? { body: { mode: "raw", raw: body } } : {}),
          },
        },
      ],
    },
  };
}

function makeTamperInstruction(): TamperInstruction {
  return {
    parameter: new QueryParameter({ name: "q" }, "original", [ReplaceValue]),
    payload: "<script>" as Brand<string, "Payload">,
    method: ReplaceValue,
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

    const results = await commandBus.dispatch<Exchange[]>(
      new ReplayCommand(scenario, config),
    );
    const result = results[0];

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

    const results = await commandBus.dispatch<Exchange[]>(
      new ReplayCommand(scenario, config),
    );
    const result = results[0];

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

    const results = await commandBus.dispatch<Exchange[]>(
      new ReplayCommand(scenario, config),
    );
    const result = results[0];

    expect(result.response.statusCode).toBe(200);

    const body = JSON.parse(
      (result.response.body as Buffer).toString("utf-8"),
    );
    expect(body.method).toBe("POST");
    expect(body.body).toBe('{"key":"value"}');

    proxy.close();
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

  it("executes a GET request and resolves without error", { timeout: 30_000 }, async () => {
    const scenario: Scenario = {
      id: "s1" as Brand<string, "ScenarioId">,
      name: "Test Newman GET",
      type: PostmanScenarioType,
      source: {
        items: [
          {
            request: {
              method: "GET",
              url: { raw: `http://127.0.0.1:${serverPort}/test` },
            },
          },
        ],
      },
    };

    await expect(
      runNewman(scenario, runNewmanProxy.port, "test-replay-id"),
    ).resolves.toBeUndefined();
  });

  it("executes a POST request with body", { timeout: 30_000 }, async () => {
    const scenario: Scenario = {
      id: "s2" as Brand<string, "ScenarioId">,
      name: "Test Newman POST",
      type: PostmanScenarioType,
      source: {
        items: [
          {
            request: {
              method: "POST",
              url: { raw: `http://127.0.0.1:${serverPort}/submit` },
              header: [{ key: "Content-Type", value: "application/json" }],
              body: { mode: "raw", raw: '{"key":"value"}' },
            },
          },
        ],
      },
    };

    await expect(
      runNewman(scenario, runNewmanProxy.port, "test-replay-id"),
    ).resolves.toBeUndefined();
  });
});

describe("PostmanPlugin multi-request", () => {
  it("sends multiple requests but only saves exchanges for the last item", { timeout: 30_000 }, async () => {
    const plugin = new PostmanPlugin();
    const proxy = await startTamperProxy([], commandBus);

    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    const scenario: Scenario = {
      id: "multi-1" as Brand<string, "ScenarioId">,
      name: "Multi Request",
      type: PostmanScenarioType,
      source: {
        items: [
          {
            request: {
              method: "GET",
              url: { raw: `http://127.0.0.1:${serverPort}/setup` },
            },
          },
          {
            request: {
              method: "GET",
              url: { raw: `http://127.0.0.1:${serverPort}/main` },
            },
          },
        ],
      },
    };

    const config: ReplayConfig = { instructions: [], proxyPort: proxy.port, replayId: "test-multi" };

    const results = await commandBus.dispatch<Exchange[]>(
      new ReplayCommand(scenario, config),
    );

    expect(results).toHaveLength(1);
    expect(results[0].response.statusCode).toBe(200);

    const body = JSON.parse(
      (results[0].response.body as Buffer).toString("utf-8"),
    );
    expect(body.url).toBe("/main");

    proxy.close();
  });
});
