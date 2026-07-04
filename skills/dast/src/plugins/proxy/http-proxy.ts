import http from "node:http";
import https from "node:https";
import net, { type AddressInfo } from "node:net";
import { TLSSocket } from "node:tls";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import selfsigned from "selfsigned";
import type {
  HttpRequest,
  HttpResponse,
  AuditMutation,
  Exchange,
} from "../../types/models.ts";
import { ExchangeId, ReplayId } from "../../types/branded.ts";
import type { ProxyPlugin, PluginContext } from "../../core/plugin.ts";
import type { CommandBus } from "../../core/command-bus.ts";
import type { MutationProxy } from "../../commands/proxy.ts";
import { CreateProxyCommand } from "../../commands/proxy.ts";
import { InterceptCommand } from "../../commands/intercept.ts";
import { ApplyMutationCommand } from "../../commands/mutation.ts";
import { SaveExchangeCommand } from "../../commands/exchange.ts";

export function sendRequest(
  request: HttpRequest,
  upstreamProxyUrl?: string,
): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(request.url);
    const isHttps = parsedUrl.protocol === "https:";
    const lib = isHttps ? https : http;

    const agent = upstreamProxyUrl
      ? isHttps
        ? new HttpsProxyAgent(upstreamProxyUrl)
        : new HttpProxyAgent(upstreamProxyUrl)
      : undefined;

    const options: https.RequestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: request.method,
      headers: { ...request.headers },
      ...(agent ? { agent } : {}),
    };

    const req = lib.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
      });
      res.on("end", () => {
        const headers: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (typeof value === "string") {
            headers[key] = value;
          } else if (Array.isArray(value)) {
            headers[key] = value.join(", ");
          }
        }

        const body = chunks.length > 0 ? Buffer.concat(chunks) : null;

        resolve({
          statusCode: res.statusCode ?? 0,
          headers,
          body,
        });
      });
      res.on("error", reject);
    });

    req.on("error", reject);

    if (request.body) {
      req.write(request.body);
    }

    req.end();
  });
}

// --- Mutation Proxy ---

export async function startMutationProxy(
  mutations: AuditMutation[],
  commandBus: CommandBus,
  upstreamProxyUrl?: string,
): Promise<MutationProxy> {
  const notAfterDate = new Date();
  notAfterDate.setFullYear(notAfterDate.getFullYear() + 10);
  const pems = await selfsigned.generate(
    [{ name: "commonName", value: "Gevanni Proxy CA" }],
    { algorithm: "sha256", notAfterDate },
  );

  async function saveFailedExchange(
    exchangeId: ExchangeId,
    replayId: ReplayId,
    request: HttpRequest,
    errorMessage: string,
    res: http.ServerResponse,
  ): Promise<void> {
    const exchange: Exchange = {
      id: exchangeId,
      request,
      response: {
        statusCode: 502,
        headers: {},
        body: Buffer.from(`Proxy error: ${errorMessage}`),
      },
    };
    await commandBus.dispatch(new SaveExchangeCommand(replayId, exchange));
    if (!res.headersSent) {
      res.writeHead(502);
    }
    res.end(`Proxy error: ${errorMessage}`);
  }

  const requestHandler = async (
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ) => {
    const isHttps = req.socket instanceof TLSSocket;
    let exchangeId: ExchangeId | undefined;
    let replayId!: ReplayId;
    let mutated!: HttpRequest;

    try {
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.from(chunk));
      }
      const body = chunks.length > 0 ? Buffer.concat(chunks) : null;

      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(req.headers)) {
        if (typeof value === "string") {
          headers[key] = value;
        }
      }
      delete headers["proxy-connection"];

      exchangeId = headers["x-gevanni-exchange-id"]
        ? ExchangeId(headers["x-gevanni-exchange-id"])
        : undefined;
      delete headers["x-gevanni-exchange-id"];

      replayId = ReplayId(headers["x-gevanni-replay-id"]!);
      delete headers["x-gevanni-replay-id"];

      const shouldMutate = headers["x-gevanni-mutate"] === "true";
      delete headers["x-gevanni-mutate"];

      const url = isHttps ? `https://${req.headers.host}${req.url}` : req.url!;

      const httpRequest: HttpRequest = {
        method: req.method!,
        url,
        headers,
        body,
      };

      mutated = shouldMutate
        ? await commandBus.pipe<HttpRequest>(
            new ApplyMutationCommand(httpRequest, mutations),
          )
        : httpRequest;

      const targetUrl = new URL(mutated.url);
      const targetIsHttps = targetUrl.protocol === "https:";
      const lib = targetIsHttps ? https : http;

      const targetAgent = upstreamProxyUrl
        ? targetIsHttps
          ? new HttpsProxyAgent(upstreamProxyUrl)
          : new HttpProxyAgent(upstreamProxyUrl)
        : undefined;

      let proxyReq: http.ClientRequest;
      try {
        proxyReq = lib.request(
          {
            hostname: targetUrl.hostname,
            port: targetUrl.port || (targetIsHttps ? 443 : 80),
            path: targetUrl.pathname + targetUrl.search,
            method: mutated.method,
            headers: { ...mutated.headers, host: targetUrl.host },
            rejectUnauthorized: false,
            autoSelectFamily: false,
            ...(targetAgent ? { agent: targetAgent } : {}),
          } as https.RequestOptions,
          (proxyRes) => {
            if (exchangeId) {
              const chunks: Buffer[] = [];
              proxyRes.on("data", (chunk: Buffer) => chunks.push(chunk));
              proxyRes.on("end", async () => {
                const responseBody =
                  chunks.length > 0 ? Buffer.concat(chunks) : null;

                const responseHeaders: Record<string, string> = {};
                for (const [key, value] of Object.entries(proxyRes.headers)) {
                  if (typeof value === "string") {
                    responseHeaders[key] = value;
                  } else if (Array.isArray(value)) {
                    responseHeaders[key] = value.join(", ");
                  }
                }

                const exchange: Exchange = {
                  id: exchangeId!,
                  request: mutated,
                  response: {
                    statusCode: proxyRes.statusCode ?? 0,
                    headers: responseHeaders,
                    body: responseBody,
                  },
                };
                await commandBus.dispatch(
                  new SaveExchangeCommand(replayId, exchange),
                );

                res.writeHead(
                  proxyRes.statusCode!,
                  proxyRes.headers as Record<string, string>,
                );
                res.end(responseBody ?? Buffer.alloc(0));
              });
            } else {
              res.writeHead(
                proxyRes.statusCode!,
                proxyRes.headers as Record<string, string>,
              );
              proxyRes.pipe(res);
            }
          },
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (exchangeId) {
          await saveFailedExchange(exchangeId, replayId, mutated, msg, res);
        } else {
          if (!res.headersSent) res.writeHead(502);
          res.end(`Proxy error: ${msg}`);
        }
        return;
      }

      proxyReq.on("error", (err) => {
        if (exchangeId) {
          saveFailedExchange(exchangeId, replayId, mutated, err.message, res);
        } else {
          if (!res.headersSent) res.writeHead(502);
          res.end(`Proxy error: ${err.message}`);
        }
      });

      if (mutated.body) {
        proxyReq.write(mutated.body);
      }
      proxyReq.end();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (exchangeId && replayId && mutated) {
        await saveFailedExchange(exchangeId, replayId, mutated, msg, res);
      } else {
        if (!res.headersSent) res.writeHead(502);
        res.end(`Proxy error: ${msg}`);
      }
    }
  };

  const server = http.createServer(requestHandler);

  const httpsServer = https.createServer(
    { key: pems.private, cert: pems.cert },
    requestHandler,
  );

  const httpsServerPort = new Promise<number>((resolve) => {
    httpsServer.listen(0, () => {
      resolve((httpsServer.address() as AddressInfo).port);
    });
  });

  server.on("connect", async (_req, socket, head) => {
    const port = await httpsServerPort;
    const serverSocket = net.connect(port, "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      serverSocket.write(head);
      serverSocket.pipe(socket);
      socket.pipe(serverSocket);
    });
    serverSocket.on("error", (err) => {
      console.error(`[PROXY-CONNECT] Error: ${err.message}`);
      socket.end();
    });
  });

  return new Promise((resolve) => {
    server.listen(0, () => {
      const addr = server.address()!;
      const port = typeof addr === "string" ? parseInt(addr) : addr.port;
      resolve({
        port,
        close: () => {
          server.closeAllConnections();
          server.close();
          httpsServer.closeAllConnections();
          httpsServer.close();
        },
      });
    });
  });
}

export interface HttpProxyConfig {
  headers?: Record<string, string>;
  upstream?: string;
}

export default class HttpProxyPlugin implements ProxyPlugin {
  readonly name = "proxy:http";
  private extraHeaders: Record<string, string>;
  private upstream?: string;

  constructor(options: HttpProxyConfig = {}) {
    this.extraHeaders = options.headers ?? {};
    this.upstream = options.upstream;
  }

  async init(context: PluginContext): Promise<void> {

    context.commandBus.register(
      CreateProxyCommand,
      async (cmd) => {
        return startMutationProxy(
          cmd.mutations,
          context.commandBus,
          this.upstream,
        );
      },
    );

    context.commandBus.register(
      InterceptCommand,
      async (cmd) => {
        // 1. Apply tamper via pipeline
        const modifiedRequest = await context.commandBus.pipe(
          new ApplyMutationCommand(cmd.request, cmd.mutations),
        );

        // 2. Merge extra config headers
        const finalRequest: HttpRequest = {
          method: modifiedRequest.method,
          url: modifiedRequest.url,
          headers: { ...this.extraHeaders, ...modifiedRequest.headers },
          body: modifiedRequest.body,
        };

        // 3. Send request to target
        const response = await sendRequest(finalRequest, this.upstream);
        return { request: modifiedRequest, response };
      },
    );
  }
}
