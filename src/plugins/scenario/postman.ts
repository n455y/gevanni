import type { Exchange, Scenario } from "../../types/models.js";
import { ScenarioType } from "../../types/branded.js";
import type { ExchangeId } from "../../types/branded.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ReplayCommand } from "../../commands/replay.js";
import { LoadExchangesCommand } from "../../commands/exchange.js";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import { randomUUID } from "node:crypto";
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

// --- Newman Runner ---

function runNewman(
  scenario: Scenario,
  proxyPort: number,
  replayId: string,
): Promise<void> {
  const source = scenario.source as { items: PostmanItem[] };
  const items = source.items;

  const newmanItems = items.map((item, index) => {
    const req = item.request;
    const url = typeof req.url === "string" ? req.url : req.url.raw;

    const isLast = index === items.length - 1;
    const header = [
      ...(Array.isArray(req.header) ? req.header : []),
      { key: "X-Gevanni-Replay-Id", value: replayId },
      ...(isLast
        ? [
            { key: "X-Gevanni-Exchange-Id", value: randomUUID() as ExchangeId },
            { key: "X-Gevanni-Tamper", value: "true" },
          ]
        : []),
    ];

    return {
      name: `${scenario.name}-${index}`,
      request: {
        method: req.method,
        url,
        header,
        ...(req.body ? { body: req.body } : {}),
      },
    };
  });

  const collection = {
    info: {
      name: "gevanni-multi-request",
      schema:
        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    item: newmanItems,
  };

  const proxyUrl = `http://127.0.0.1:${proxyPort}`;

  return new Promise((resolve, reject) => {
    newman.run(
      {
        collection,
        insecure: true,
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
      await runNewman(scenario, config.proxyPort, config.replayId);
      const exchanges = await commandBus.dispatch<Exchange[]>(
        new LoadExchangesCommand(config.replayId),
      );
      if (exchanges.length === 0) {
        throw new Error(
          `No exchange captured for replayId: ${config.replayId}`,
        );
      }
      return exchanges;
    });
  }
}

class PostmanScenarioType extends ScenarioType {}

export { PostmanPlugin, PostmanScenarioType, runNewman };
export type { PostmanHeader, PostmanBody, PostmanRequest, PostmanItem };
