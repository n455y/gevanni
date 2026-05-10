import { describe, it, expect, beforeEach, afterEach } from "vitest";
import http from "node:http";
import https from "node:https";
import selfsigned from "selfsigned";
import { HttpsProxyAgent } from "https-proxy-agent";
import { InMemoryCommandBus } from "../../core/command-bus.js";
import { InMemoryEventBus } from "../../core/event-bus.js";
import { HttpProxyPlugin } from "./http-proxy.js";
import { InterceptCommand } from "../../commands/intercept.js";
import { ApplyMutationCommand } from "../../commands/mutation.js";
import { startMutationProxy } from "./http-proxy.js";
import type { HttpRequest, HttpResponse } from "../../types/models.js";
import { AuditMutation } from "../../types/models.js";
import type { Exchange } from "../../types/models.js";
import type { Brand } from "../../types/branded.js";
import { ReplaceValue } from "../../types/branded.js";
import { QueryParameter } from "../parameter/query.js";
import { LoadExchangesCommand, SaveExchangeCommand } from "../../commands/exchange.js";

let commandBus: InMemoryCommandBus;
let server: http.Server;
let serverPort: number;

const testExchanges = new Map<string, Exchange[]>();

beforeEach(async () => {
  commandBus = new InMemoryCommandBus();

  testExchanges.clear();

  commandBus.register(SaveExchangeCommand, async (cmd) => {
    const existing = testExchanges.get(cmd.replayId) ?? [];
    existing.push(cmd.exchange);
    testExchanges.set(cmd.replayId, existing);
  });

  commandBus.register(LoadExchangesCommand, async (cmd) => {
    return testExchanges.get(cmd.replayId) ?? [];
  });

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
    const plugin = new HttpProxyPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    // Register a no-op ApplyMutationCommand handler
    commandBus.register(
      ApplyMutationCommand,
      async (_cmd, request) => request,
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

  it("pipes through ApplyMutationCommand before sending", async () => {
    const plugin = new HttpProxyPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    // Register a tamper handler that modifies the URL
    commandBus.register(
      ApplyMutationCommand,
      async (_cmd, request) => ({
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
    const plugin = new HttpProxyPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    commandBus.register(
      ApplyMutationCommand,
      async (_cmd, request) => request,
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
    const plugin = new HttpProxyPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {
        headers: { "X-Custom": "injected" },
      },
    });

    commandBus.register(
      ApplyMutationCommand,
      async (_cmd, request) => request,
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
    const plugin = new HttpProxyPlugin();
    await plugin.init({
      commandBus,
      eventBus: new InMemoryEventBus(),
      config: {},
    });

    commandBus.register(
      ApplyMutationCommand,
      async (_cmd, request) => ({
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

describe("startMutationProxy", () => {
  it("starts a proxy that forwards requests via tamper pipeline", async () => {
    const proxy = await startMutationProxy([], commandBus);

    commandBus.register(
      ApplyMutationCommand,
      async (_cmd, request) => request,
    );

    const response = await new Promise<{ statusCode: number; body: string }>((resolve, reject) => {
      const req = http.request(
        {
          hostname: "127.0.0.1",
          port: proxy.port,
          method: "GET",
          path: `http://127.0.0.1:${serverPort}/proxy-test`,
          headers: { host: `127.0.0.1:${serverPort}` },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("end", () => {
            resolve({
              statusCode: res.statusCode ?? 0,
              body: Buffer.concat(chunks).toString("utf-8"),
            });
          });
        },
      );
      req.on("error", reject);
      req.end();
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.url).toBe("/proxy-test");

    proxy.close();
  });

  it("applies tamper mutations to requests passing through", async () => {
    const mutations: AuditMutation[] = [
      new QueryParameter({ name: "q" }, "original", [ReplaceValue]).createMutation(
        "<script>" as Brand<string, "Payload">,
        ReplaceValue,
      ),
    ];

    commandBus.register(
      ApplyMutationCommand,
      async (_cmd, request) => {
        const url = new URL(request.url);
        const searchParams = new URLSearchParams(url.search);
        for (const instr of _cmd.mutations) {
          const paramName = (instr.target.location as { name: string }).name;
          searchParams.set(paramName, instr.payload as string);
        }
        url.search = searchParams.toString();
        return { ...request, url: url.toString() };
      },
    );

    const proxy = await startMutationProxy(mutations, commandBus);

    const response = await new Promise<{ statusCode: number; body: string }>((resolve, reject) => {
      const req = http.request(
        {
          hostname: "127.0.0.1",
          port: proxy.port,
          method: "GET",
          path: `http://127.0.0.1:${serverPort}/test?q=original`,
          headers: { host: `127.0.0.1:${serverPort}`, "x-gevanni-mutate": "true" },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("end", () => {
            resolve({
              statusCode: res.statusCode ?? 0,
              body: Buffer.concat(chunks).toString("utf-8"),
            });
          });
        },
      );
      req.on("error", reject);
      req.end();
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.url).toBe("/test?q=%3Cscript%3E");

    proxy.close();
  });

  it("saves exchange when X-Gevanni-Exchange-Id header is present", async () => {
    const replayId = "replay-test-001";
    const proxy = await startMutationProxy([], commandBus);

    commandBus.register(
      ApplyMutationCommand,
      async (_cmd, request) => request,
    );

    const response = await new Promise<{ statusCode: number; body: string }>(
      (resolve, reject) => {
        const req = http.request(
          {
            hostname: "127.0.0.1",
            port: proxy.port,
            method: "GET",
            path: `http://127.0.0.1:${serverPort}/exchange-test`,
            headers: {
              host: `127.0.0.1:${serverPort}`,
              "x-gevanni-exchange-id": replayId,
              "x-gevanni-replay-id": replayId,
            },
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (chunk: Buffer) => chunks.push(chunk));
            res.on("end", () => {
              resolve({
                statusCode: res.statusCode ?? 0,
                body: Buffer.concat(chunks).toString("utf-8"),
              });
            });
          },
        );
        req.on("error", reject);
        req.end();
      },
    );

    expect(response.statusCode).toBe(200);

    const exchanges = await commandBus.dispatch<Exchange[]>(
      new LoadExchangesCommand(replayId),
    );
    expect(exchanges).toHaveLength(1);
    expect(exchanges[0].request.method).toBe("GET");
    expect(exchanges[0].response.statusCode).toBe(200);

    proxy.close();
  });

  it("does not save exchange when X-Gevanni-Exchange-Id header is absent", async () => {
    const proxy = await startMutationProxy([], commandBus);

    commandBus.register(
      ApplyMutationCommand,
      async (_cmd, request) => request,
    );

    const response = await new Promise<{ statusCode: number; body: string }>(
      (resolve, reject) => {
        const req = http.request(
          {
            hostname: "127.0.0.1",
            port: proxy.port,
            method: "GET",
            path: `http://127.0.0.1:${serverPort}/no-header-test`,
            headers: { host: `127.0.0.1:${serverPort}` },
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (chunk: Buffer) => chunks.push(chunk));
            res.on("end", () => {
              resolve({
                statusCode: res.statusCode ?? 0,
                body: Buffer.concat(chunks).toString("utf-8"),
              });
            });
          },
        );
        req.on("error", reject);
        req.end();
      },
    );

    expect(response.statusCode).toBe(200);

    // Verify no exchanges were saved
    expect(testExchanges.size).toBe(0);

    proxy.close();
  });

  describe("HTTPS MITM", () => {
    let httpsTarget: https.Server;
    let httpsTargetPort: number;

    beforeEach(async () => {
      const targetPems = await selfsigned.generate(
        [{ name: "commonName", value: "test-server" }],
        { algorithm: "sha256" },
      );

      httpsTarget = https.createServer(
        { key: targetPems.private, cert: targetPems.cert },
        (req, res) => {
          let body = "";
          req.on("data", (chunk) => {
            body += chunk;
          });
          req.on("end", () => {
            res.writeHead(200, {
              "Content-Type": "application/json",
              "X-Test": "https-ok",
            });
            res.end(
              JSON.stringify({
                method: req.method,
                url: req.url,
                headers: req.headers,
                body,
              }),
            );
          });
        },
      );

      await new Promise<void>((resolve) => {
        httpsTarget.listen(0, () => resolve());
      });
      const addr = httpsTarget.address();
      if (addr && typeof addr === "object") {
        httpsTargetPort = addr.port;
      } else {
        throw new Error("Failed to get HTTPS target port");
      }
    });

    afterEach(() => {
      httpsTarget.close();
    });

    it("intercepts HTTPS requests via CONNECT tunnel", async () => {
      const proxy = await startMutationProxy([], commandBus);

      commandBus.register(
        ApplyMutationCommand,
        async (_cmd, request) => request,
      );

      const agent = new HttpsProxyAgent(`http://127.0.0.1:${proxy.port}`);

      const response = await new Promise<{ statusCode: number; body: string }>(
        (resolve, reject) => {
          const req = https.request(
            {
              hostname: "127.0.0.1",
              port: httpsTargetPort,
              path: "/https-test",
              method: "GET",
              agent,
              rejectUnauthorized: false,
            },
            (res) => {
              const chunks: Buffer[] = [];
              res.on("data", (chunk: Buffer) => chunks.push(chunk));
              res.on("end", () => {
                resolve({
                  statusCode: res.statusCode ?? 0,
                  body: Buffer.concat(chunks).toString("utf-8"),
                });
              });
            },
          );
          req.on("error", reject);
          req.end();
        },
      );

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.url).toBe("/https-test");

      proxy.close();
    }, 15000);

    it("saves exchange for HTTPS requests", async () => {
      const replayId = "replay-https-001";
      const proxy = await startMutationProxy([], commandBus);

      commandBus.register(
        ApplyMutationCommand,
        async (_cmd, request) => request,
      );

      const agent = new HttpsProxyAgent(`http://127.0.0.1:${proxy.port}`);

      const response = await new Promise<{ statusCode: number; body: string }>(
        (resolve, reject) => {
          const req = https.request(
            {
              hostname: "127.0.0.1",
              port: httpsTargetPort,
              path: "/exchange-https-test",
              method: "GET",
              agent,
              rejectUnauthorized: false,
              headers: {
                "x-gevanni-exchange-id": replayId,
                "x-gevanni-replay-id": replayId,
              },
            },
            (res) => {
              const chunks: Buffer[] = [];
              res.on("data", (chunk: Buffer) => chunks.push(chunk));
              res.on("end", () => {
                resolve({
                  statusCode: res.statusCode ?? 0,
                  body: Buffer.concat(chunks).toString("utf-8"),
                });
              });
            },
          );
          req.on("error", reject);
          req.end();
        },
      );

      expect(response.statusCode).toBe(200);

      const exchanges = await commandBus.dispatch<Exchange[]>(
        new LoadExchangesCommand(replayId),
      );
      expect(exchanges).toHaveLength(1);
      expect(exchanges[0].request.method).toBe("GET");
      expect(exchanges[0].request.url).toContain("https://");
      expect(exchanges[0].response.statusCode).toBe(200);

      proxy.close();
    }, 15000);
  });
});
