import http from "node:http";
import https from "node:https";
import type { HttpRequest, HttpResponse } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { InterceptCommand } from "../../commands/intercept.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";

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

        const body =
          chunks.length > 0 ? Buffer.concat(chunks) : null;

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

function createHttpProxyPlugin(): Plugin {
  return {
    name: "http-proxy",

    async init(context: PluginContext): Promise<void> {
      const commandBus = context.commandBus;
      const extraHeaders = (context.config.headers ?? {}) as Record<
        string,
        string
      >;

      commandBus.register(
        InterceptCommand,
        async (cmd: InterceptCommand) => {
          // 1. Apply tamper via pipeline
          const modifiedRequest = await commandBus.pipe(
            new ApplyTamperCommand(cmd.request, cmd.instructions),
          );

          // 2. Merge extra config headers
          const finalRequest: HttpRequest = {
            method: modifiedRequest.method,
            url: modifiedRequest.url,
            headers: { ...extraHeaders, ...modifiedRequest.headers },
            body: modifiedRequest.body,
          };

          // 3. Send request to target
          const response = await sendRequest(finalRequest);
          return { request: modifiedRequest, response };
        },
      );
    },
  };
}

export { createHttpProxyPlugin, sendRequest };
