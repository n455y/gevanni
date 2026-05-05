import http from "node:http";
import https from "node:https";
import type { HttpRequest, HttpResponse, Scenario } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ReplayCommand } from "../../commands/replay.js";
import { InterceptCommand } from "../../commands/intercept.js";

// --- Postman Collection types (v2.1 subset) ---

interface PostmanHeader {
  key: string;
  value: string;
}

interface PostmanBody {
  mode?: string;
  raw?: string;
}

interface PostmanRequest {
  method: string;
  url: { raw: string } | string;
  header?: PostmanHeader[];
  body?: PostmanBody;
}

interface PostmanItem {
  request: PostmanRequest;
}

// --- Helpers ---

function buildRequest(scenario: Scenario): HttpRequest {
  const source = scenario.source as { item: PostmanItem };
  const item = source.item;
  const req = item.request;

  // Extract URL
  const url = typeof req.url === "string" ? req.url : req.url.raw;

  // Extract headers
  const headers: Record<string, string> = {};
  if (Array.isArray(req.header)) {
    for (const h of req.header) {
      headers[h.key] = h.value;
    }
  }

  // Extract body
  let body: Buffer | null = null;
  if (req.body?.raw != null) {
    body = Buffer.from(req.body.raw, "utf-8");
  }

  return {
    method: req.method,
    url,
    headers,
    body,
  };
}

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
        const resHeaders: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (typeof value === "string") {
            resHeaders[key] = value;
          } else if (Array.isArray(value)) {
            resHeaders[key] = value.join(", ");
          }
        }

        const resBody =
          chunks.length > 0 ? Buffer.concat(chunks) : null;

        resolve({
          statusCode: res.statusCode ?? 0,
          headers: resHeaders,
          body: resBody,
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

// --- Plugin ---

class PostmanPlugin implements Plugin {
  readonly name = "postman";

  async init(context: PluginContext): Promise<void> {
    const commandBus = context.commandBus;

    commandBus.register(ReplayCommand, async (cmd) => {
      const { scenario, instructions } = cmd;

      // Build HttpRequest from scenario source
      const request = buildRequest(scenario);

      if (instructions.length > 0) {
        // Delegate to proxy for tampered requests
        return commandBus.dispatch(
          new InterceptCommand(request, instructions),
        );
      }

      // Send directly if no tampering needed
      const response = await sendRequest(request);
      return { request, response };
    });
  }
}

export { PostmanPlugin, buildRequest, sendRequest };
export type { PostmanHeader, PostmanBody, PostmanRequest, PostmanItem };
