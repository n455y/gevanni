import http from "node:http";
import type {
  HttpRequest,
  HttpResponse,
  Scenario,
  TamperInstruction,
} from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import type { CommandBus } from "../../core/command-bus.js";
import { ReplayCommand } from "../../commands/replay.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import newman from "newman";

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

      const httpRequest: HttpRequest = {
        method: req.method!,
        url: req.url!,
        headers,
        body,
      };

      const tampered = await commandBus.pipe<HttpRequest>(
        new ApplyTamperCommand(httpRequest, instructions),
      );

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
          res.writeHead(
            proxyRes.statusCode!,
            proxyRes.headers as Record<string, string>,
          );
          proxyRes.pipe(res);
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

// --- Newman Runner ---

function runNewman(
  scenario: Scenario,
  proxyPort?: number,
): Promise<HttpResponse> {
  const source = scenario.source as { item: PostmanItem };
  const item = source.item;
  const req = item.request;

  // Newman's runtime does not resolve { raw: "..." } URL objects correctly,
  // so we must pass the URL as a plain string.
  const url = typeof req.url === "string" ? req.url : req.url.raw;

  const newmanItem = {
    name: scenario.name,
    request: {
      method: req.method,
      url,
      ...(Array.isArray(req.header) && req.header.length > 0
        ? { header: req.header }
        : {}),
      ...(req.body ? { body: req.body } : {}),
    },
  };

  const collection = {
    info: {
      name: "gevanni-single-request",
      schema:
        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    item: [newmanItem],
  };

  let savedHttpProxy: string | undefined;
  let savedNoProxy: string | undefined;
  if (proxyPort !== undefined) {
    savedHttpProxy = process.env.HTTP_PROXY;
    savedNoProxy = process.env.NO_PROXY;
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    process.env.NO_PROXY = "";
  }

  return new Promise((resolve, reject) => {
    newman.run({ collection, reporters: [] }, (err, summary) => {
      if (proxyPort !== undefined) {
        if (savedHttpProxy !== undefined) {
          process.env.HTTP_PROXY = savedHttpProxy;
        } else {
          delete process.env.HTTP_PROXY;
        }
        if (savedNoProxy !== undefined) {
          process.env.NO_PROXY = savedNoProxy;
        } else {
          delete process.env.NO_PROXY;
        }
      }

      if (err) {
        reject(err);
        return;
      }

      const exec = summary.run.executions[0];

      const res = exec.response;
      if (!res) {
        reject(new Error("No response returned from newman"));
        return;
      }

      const headers: Record<string, string> = {};
      for (const h of res.headers.all()) {
        headers[h.key.toLowerCase()] = h.value;
      }

      resolve({
        statusCode: res.code,
        headers,
        body: Buffer.from(res.stream ?? Buffer.alloc(0)),
      });
    });
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
        // Start tamper proxy and run Newman through it
        const proxy = await startTamperProxy(instructions, commandBus);
        try {
          const response = await runNewman(scenario, proxy.port);
          return { request, response };
        } finally {
          proxy.close();
        }
      }

      // Send directly if no tampering needed
      const response = await runNewman(scenario);
      return { request, response };
    });
  }
}

export { PostmanPlugin, buildRequest, runNewman, startTamperProxy };
export type { PostmanHeader, PostmanBody, PostmanRequest, PostmanItem };
