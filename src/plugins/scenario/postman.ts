import type { HttpRequest, HttpResponse, Scenario } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ReplayCommand } from "../../commands/replay.js";
import { InterceptCommand } from "../../commands/intercept.js";
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

function runNewman(scenario: Scenario): Promise<HttpResponse> {
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

  return new Promise((resolve, reject) => {
    newman.run({ collection, reporters: [] }, (err, summary) => {
      if (err) {
        reject(err);
        return;
      }

      const exec = summary.run.executions[0];

      if (exec.requestError) {
        reject(exec.requestError);
        return;
      }

      const res = exec.response;
      if (!res) {
        reject(new Error("No response returned from newman"));
        return;
      }

      const headers: Record<string, string> = {};
      const headerMembers = res.headers?.members ?? [];
      for (const h of headerMembers) {
        headers[h.key.toLowerCase()] = h.value;
      }

      resolve({
        statusCode: res.code,
        headers,
        body: Buffer.from(res.stream),
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
        // Delegate to proxy for tampered requests
        return commandBus.dispatch(
          new InterceptCommand(request, instructions),
        );
      }

      // Send directly if no tampering needed
      const response = await runNewman(scenario);
      return { request, response };
    });
  }
}

export { PostmanPlugin, buildRequest, runNewman };
export type { PostmanHeader, PostmanBody, PostmanRequest, PostmanItem };
