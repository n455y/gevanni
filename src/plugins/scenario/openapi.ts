import type { Exchange, Scenario } from "../../types/models.ts";
import { ExchangeId } from "../../types/branded.ts";
import type { ReplayId } from "../../types/branded.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import { ReplayCommand } from "../../commands/replay.ts";
import { LoadExchangesCommand } from "../../commands/exchange.ts";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import http from "node:http";
import https from "node:https";
import { randomUUID } from "node:crypto";
import {
  type OpenApiOperation,
  type OpenApiParameter,
  type OpenApiRequestBody,
  defaultValueForSchema,
} from "../loader/openapi-loader.ts";

// --- Request building ---

export function buildUrl(op: OpenApiOperation): string {
  let resolvedPath = op.path;
  const queryParams: string[] = [];
  const headerParams: Record<string, string> = {};

  for (const param of op.parameters) {
    const value = String(
      defaultValueForSchema(param.schema, param.example),
    );

    switch (param.in) {
      case "path":
        resolvedPath = resolvedPath.replace(`{${param.name}}`, encodeURIComponent(value));
        break;
      case "query":
        queryParams.push(`${encodeURIComponent(param.name)}=${encodeURIComponent(value)}`);
        break;
      case "header":
        headerParams[param.name] = value;
        break;
    }
  }

  const base = op.baseUrl.replace(/\/$/, "");
  const path = resolvedPath.startsWith("/") ? resolvedPath : `/${resolvedPath}`;
  let url = `${base}${path}`;
  if (queryParams.length > 0) {
    url += `?${queryParams.join("&")}`;
  }

  return url;
}

export function buildHeaders(
  op: OpenApiOperation,
  proxyPort: number,
  replayId: ReplayId,
): Record<string, string> {
  const headers: Record<string, string> = {
    "X-Gevanni-Replay-Id": replayId,
  };

  for (const param of op.parameters) {
    if (param.in === "header") {
      headers[param.name] = String(
        defaultValueForSchema(param.schema, param.example),
      );
    }
  }

  if (op.requestBody) {
    headers["Content-Type"] = op.requestBody.contentType;
  }

  return headers;
}

export function buildBody(requestBody?: OpenApiRequestBody): string | null {
  if (!requestBody) return null;
  const value = defaultValueForSchema(requestBody.schema, requestBody.example);
  return typeof value === "string" ? value : JSON.stringify(value);
}

// --- HTTP sender ---

function sendViaProxy(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: string | null,
  proxyPort: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === "https:";
    const proxyUrl = `http://127.0.0.1:${proxyPort}`;
    const agent = isHttps
      ? new HttpsProxyAgent(proxyUrl)
      : new HttpProxyAgent(proxyUrl);

    const options: https.RequestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      headers,
      agent,
      rejectUnauthorized: false,
    };

    const req = (isHttps ? https : http).request(options, (res) => {
      res.resume();
      res.on("end", resolve);
      res.on("error", reject);
    });

    req.on("error", reject);

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

// --- Plugin ---

export class OpenApiPlugin implements Plugin {
  readonly name = "openapi";

  async init(context: PluginContext): Promise<void> {
    const { commandBus } = context;
    context.commandBus.register(ReplayCommand, async (cmd) => {
      const { scenario, config } = cmd;
      const op = scenario.source as OpenApiOperation;

      const url = buildUrl(op);
      const headers = buildHeaders(op, config.proxyPort, config.replayId);
      const body = buildBody(op.requestBody);

      // Last request in multi-request scenario gets exchange tracking + mutation
      headers["X-Gevanni-Exchange-Id"] = ExchangeId(randomUUID());
      headers["X-Gevanni-Mutate"] = "true";

      await sendViaProxy(op.method, url, headers, body, config.proxyPort);

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

export { OpenApiScenarioType } from "../loader/openapi-loader.ts";
