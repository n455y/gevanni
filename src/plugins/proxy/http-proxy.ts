import http from "node:http";
import https from "node:https";
import type {
  HttpRequest,
  HttpResponse,
  TamperInstruction,
  Exchange,
} from "../../types/models.js";
import type { ExchangeId } from "../../types/branded.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import type { CommandBus } from "../../core/command-bus.js";
import { InterceptCommand } from "../../commands/intercept.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import { SaveExchangeCommand } from "../../commands/exchange.js";

function sendRequest(request: HttpRequest): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(request.url);
    const isHttps = parsedUrl.protocol === "https:";
    const lib = isHttps ? https : http;

    const options: https.RequestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: request.method,
      headers: { ...request.headers },
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

// --- Tamper Proxy ---

interface TamperProxy {
  port: number;
  close: () => void;
}

function startTamperProxy(
  instructions: TamperInstruction[],
  commandBus: CommandBus,
): Promise<TamperProxy> {
  const server = http.createServer(async (req, res) => {
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

      const exchangeId = headers["x-gevanni-exchange-id"] as
        | ExchangeId
        | undefined;
      delete headers["x-gevanni-exchange-id"];

      const replayId = headers["x-gevanni-replay-id"];
      delete headers["x-gevanni-replay-id"];

      const shouldTamper = headers["x-gevanni-tamper"] === "true";
      delete headers["x-gevanni-tamper"];

      const httpRequest: HttpRequest = {
        method: req.method!,
        url: req.url!,
        headers,
        body,
      };

      const tampered = shouldTamper
        ? await commandBus.pipe<HttpRequest>(
            new ApplyTamperCommand(httpRequest, instructions),
          )
        : httpRequest;

      const targetUrl = new URL(tampered.url);
      const proxyReq = http.request(
        {
          hostname: targetUrl.hostname,
          port: targetUrl.port || 80,
          path: targetUrl.pathname + targetUrl.search,
          method: tampered.method,
          headers: { ...tampered.headers, host: targetUrl.host },
        },
        (proxyRes) => {
          if (exchangeId) {
            // Buffer response for exchange capture
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
                id: exchangeId,
                request: tampered,
                response: {
                  statusCode: proxyRes.statusCode ?? 0,
                  headers: responseHeaders,
                  body: responseBody,
                },
              };
              await commandBus.dispatch(
                new SaveExchangeCommand(replayId!, exchange),
              );

              res.writeHead(
                proxyRes.statusCode!,
                proxyRes.headers as Record<string, string>,
              );
              res.end(responseBody ?? Buffer.alloc(0));
            });
          } else {
            // Stream response without buffering
            res.writeHead(
              proxyRes.statusCode!,
              proxyRes.headers as Record<string, string>,
            );
            proxyRes.pipe(res);
          }
        },
      );

      proxyReq.on("error", (err) => {
        if (!res.headersSent) {
          res.writeHead(502);
        }
        res.end(`Proxy error: ${err.message}`);
      });

      if (tampered.body) {
        proxyReq.write(tampered.body);
      }
      proxyReq.end();
    } catch (err) {
      if (!res.headersSent) {
        res.writeHead(500);
      }
      res.end(`Proxy error: ${err}`);
    }
  });

  return new Promise((resolve) => {
    server.listen(0, () => {
      const addr = server.address()!;
      const port = typeof addr === "string" ? parseInt(addr) : addr.port;
      resolve({
        port,
        close: () => server.closeAllConnections(),
      });
    });
  });
}

class HttpProxyPlugin implements Plugin {
  readonly name = "http-proxy";
  private extraHeaders: Record<string, string> = {};

  async init(context: PluginContext): Promise<void> {
    this.extraHeaders = (context.config.headers ?? {}) as Record<
      string,
      string
    >;

    context.commandBus.register(
      InterceptCommand,
      async (cmd: InterceptCommand) => {
        // 1. Apply tamper via pipeline
        const modifiedRequest = await context.commandBus.pipe(
          new ApplyTamperCommand(cmd.request, cmd.instructions),
        );

        // 2. Merge extra config headers
        const finalRequest: HttpRequest = {
          method: modifiedRequest.method,
          url: modifiedRequest.url,
          headers: { ...this.extraHeaders, ...modifiedRequest.headers },
          body: modifiedRequest.body,
        };

        // 3. Send request to target
        const response = await sendRequest(finalRequest);
        return { request: modifiedRequest, response };
      },
    );
  }
}

export { HttpProxyPlugin, sendRequest, startTamperProxy };
export type { TamperProxy };
