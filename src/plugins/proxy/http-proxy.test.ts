import { describe, it, expect, beforeEach, afterEach } from "vitest";
import http from "node:http";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { createHttpProxyPlugin } from "./http-proxy.js";
import { InterceptCommand } from "../../commands/intercept.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import type { HttpRequest, HttpResponse } from "../../types/models.js";

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

function makeRequest(url: string, method = "GET"): HttpRequest {
  return {
    method,
    url,
    headers: { "content-type": "application/json" },
    body: null,
  };
}

describe("HttpProxyPlugin", () => {
  it("registers the plugin and intercepts an HTTP request", async () => {
    const plugin = createHttpProxyPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    // Register a no-op ApplyTamperCommand handler
    commandBus.register(
      ApplyTamperCommand,
      async (_cmd: ApplyTamperCommand, request: HttpRequest) => request,
    );

    const request = makeRequest(`http://127.0.0.1:${serverPort}/test`);

    const result = await commandBus.dispatch<{ request: HttpRequest; response: HttpResponse }>(
      new InterceptCommand(request, []),
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

  it("pipes through ApplyTamperCommand before sending", async () => {
    const plugin = createHttpProxyPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    // Register a tamper handler that modifies the URL
    commandBus.register(
      ApplyTamperCommand,
      async (_cmd: ApplyTamperCommand, request: HttpRequest) => ({
        ...request,
        url: request.url.replace("/original", "/modified"),
      }),
    );

    const request = makeRequest(
      `http://127.0.0.1:${serverPort}/original`,
    );

    const result = await commandBus.dispatch<{ request: HttpRequest; response: HttpResponse }>(
      new InterceptCommand(request, []),
    );

    // The modified URL should have been sent
    const body = JSON.parse(
      (result.response.body as Buffer).toString("utf-8"),
    );
    expect(body.url).toBe("/modified");
  });

  it("sends POST request with body", async () => {
    const plugin = createHttpProxyPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    commandBus.register(
      ApplyTamperCommand,
      async (_cmd: ApplyTamperCommand, request: HttpRequest) => request,
    );

    const request: HttpRequest = {
      method: "POST",
      url: `http://127.0.0.1:${serverPort}/submit`,
      headers: { "content-type": "application/json" },
      body: Buffer.from('{"key":"value"}', "utf-8"),
    };

    const result = await commandBus.dispatch<{ request: HttpRequest; response: HttpResponse }>(
      new InterceptCommand(request, []),
    );

    expect(result.response.statusCode).toBe(200);

    const body = JSON.parse(
      (result.response.body as Buffer).toString("utf-8"),
    );
    expect(body.method).toBe("POST");
    expect(body.body).toBe('{"key":"value"}');
  });

  it("adds extra headers from config", async () => {
    const plugin = createHttpProxyPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {
        headers: { "X-Custom": "injected" },
      },
    });

    commandBus.register(
      ApplyTamperCommand,
      async (_cmd: ApplyTamperCommand, request: HttpRequest) => request,
    );

    const request = makeRequest(`http://127.0.0.1:${serverPort}/test`);

    const result = await commandBus.dispatch<{ request: HttpRequest; response: HttpResponse }>(
      new InterceptCommand(request, []),
    );

    const body = JSON.parse(
      (result.response.body as Buffer).toString("utf-8"),
    );
    expect(body.headers["x-custom"]).toBe("injected");
  });

  it("returns the modified request in the result", async () => {
    const plugin = createHttpProxyPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    commandBus.register(
      ApplyTamperCommand,
      async (_cmd: ApplyTamperCommand, request: HttpRequest) => ({
        ...request,
        headers: { ...request.headers, "x-tampered": "true" },
      }),
    );

    const request = makeRequest(`http://127.0.0.1:${serverPort}/test`);

    const result = await commandBus.dispatch<{ request: HttpRequest; response: HttpResponse }>(
      new InterceptCommand(request, []),
    );

    // The returned request should be the modified one from the tamper pipeline
    expect(result.request.headers["x-tampered"]).toBe("true");
  });
});
