import type { HttpRequest, Exchange, Scenario } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ReplayCommand } from "../../commands/replay.js";
import { LoadExchangesCommand } from "../../commands/exchange.js";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
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

  const url = typeof req.url === "string" ? req.url : req.url.raw;

  const headers: Record<string, string> = {};
  if (Array.isArray(req.header)) {
    for (const h of req.header) {
      headers[h.key] = h.value;
    }
  }

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

// --- Newman Runner ---

function runNewman(
  scenario: Scenario,
  proxyPort: number,
  replayId: string,
): Promise<void> {
  const source = scenario.source as { item: PostmanItem };
  const item = source.item;
  const req = item.request;

  const url = typeof req.url === "string" ? req.url : req.url.raw;

  const header = [
    ...(Array.isArray(req.header) ? req.header : []),
    { key: "X-Gevanni-Replay-Id", value: replayId },
  ];

  const newmanItem = {
    name: scenario.name,
    request: {
      method: req.method,
      url,
      header,
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

  const proxyUrl = `http://127.0.0.1:${proxyPort}`;

  return new Promise((resolve, reject) => {
    newman.run(
      {
        collection,
        reporters: [],
        requestAgents: {
          http: new HttpProxyAgent(proxyUrl),
          https: new HttpsProxyAgent(proxyUrl),
        },
      },
      (err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      },
    );
  });
}

// --- Plugin ---

class PostmanPlugin implements Plugin {
  readonly name = "postman";

  async init(context: PluginContext): Promise<void> {
    const { commandBus } = context;
    context.commandBus.register(ReplayCommand, async (cmd: ReplayCommand) => {
      const { scenario, config } = cmd;
      const request = buildRequest(scenario);
      await runNewman(scenario, config.proxyPort, config.replayId);
      const exchanges = await commandBus.dispatch<Exchange[]>(
        new LoadExchangesCommand(config.replayId),
      );
      return exchanges[0];
    });
  }
}

export { PostmanPlugin, buildRequest, runNewman };
export type { PostmanHeader, PostmanBody, PostmanRequest, PostmanItem };
