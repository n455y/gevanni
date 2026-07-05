import { type Exchange, type HttpResponse, ReplayResult } from "../../types/models.ts";
import { ExchangeId } from "../../types/branded.ts";
import type { ReplayId } from "../../types/branded.ts";
import type { ScenarioPlugin, PluginContext } from "../../core/plugin.ts";
import { ReplayCommand } from "../../commands/replay.ts";
import { LoadExchangesCommand } from "../../commands/exchange.ts";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import http from "node:http";
import https from "node:https";
import { randomUUID } from "node:crypto";
import {
  type OpenApiOperation,
  type OpenApiRequestBody,
  type OpenApiScenarioSource,
  type OpenApiSecurityScheme,
  defaultValueForSchema,
} from "../loader/openapi-loader.ts";

// --- Runtime expression resolver ---

export function resolveRuntimeExpression(
  expr: string,
  response: HttpResponse,
): string {
  if (expr.startsWith("$response.body#")) {
    const pointer = expr.slice("$response.body#".length);
    const body = response.body?.toString("utf-8") ?? "{}";
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      return "";
    }
    const value = resolveJsonPointer(parsed, pointer);
    return String(value ?? "");
  }

  if (expr.startsWith("$response.header#")) {
    const raw = expr.slice("$response.header#".length);
    const headerName = raw.startsWith("/")
      ? raw.slice(1).toLowerCase()
      : raw.toLowerCase();
    return response.headers[headerName] ?? "";
  }

  return expr;
}

function resolveJsonPointer(data: unknown, pointer: string): unknown {
  if (pointer === "" || pointer === "/") return data;
  const tokens = pointer.split("/").slice(1);
  let current: unknown = data;
  for (const token of tokens) {
    if (current === null || current === undefined) return undefined;
    if (Array.isArray(current)) {
      current = current[parseInt(token, 10)];
    } else if (typeof current === "object") {
      current = (current as Record<string, unknown>)[decodeURIComponent(token)];
    } else {
      return undefined;
    }
  }
  return current;
}

// --- Request building ---

export function buildUrl(
  op: OpenApiOperation,
  overrides?: Record<string, string>,
): string {
  let resolvedPath = op.path;
  const queryParams: string[] = [];

  for (const param of op.parameters) {
    const value =
      overrides?.[param.name] ??
      String(defaultValueForSchema(param.schema, param.example));

    switch (param.in) {
      case "path":
        resolvedPath = resolvedPath.replace(
          `{${param.name}}`,
          encodeURIComponent(value),
        );
        break;
      case "query":
        queryParams.push(
          `${encodeURIComponent(param.name)}=${encodeURIComponent(value)}`,
        );
        break;
    }
  }

  const base = op.baseUrl.replace(/\/$/, "");
  const path = resolvedPath.startsWith("/")
    ? resolvedPath
    : `/${resolvedPath}`;
  let url = `${base}${path}`;
  if (queryParams.length > 0) {
    url += `?${queryParams.join("&")}`;
  }

  return url;
}

function applySecurity(
  headers: Record<string, string>,
  security: string[] | undefined,
  schemes: Record<string, OpenApiSecurityScheme> | undefined,
  tokens: Record<string, string> | undefined,
): void {
  if (!security || !schemes) return;
  for (const name of security) {
    const scheme = schemes[name];
    const token = tokens?.[name];
    if (!scheme || !token) continue;
    if (scheme.type === "http" && scheme.scheme === "bearer") {
      headers["Authorization"] = `Bearer ${token}`;
    } else if (scheme.type === "oauth2") {
      headers["Authorization"] = `Bearer ${token}`;
    } else if (
      scheme.type === "apiKey" &&
      scheme.in === "header" &&
      scheme.name
    ) {
      headers[scheme.name] = token;
    }
  }
}

export function buildHeaders(
  op: OpenApiOperation,
  replayId: ReplayId,
  overrides?: Record<string, string>,
  securitySchemes?: Record<string, OpenApiSecurityScheme>,
  tokens?: Record<string, string>,
): Record<string, string> {
  const headers: Record<string, string> = {
    "X-Gevanni-Replay-Id": replayId,
  };

  for (const param of op.parameters) {
    if (param.in === "header") {
      headers[param.name] =
        overrides?.[param.name] ??
        String(defaultValueForSchema(param.schema, param.example));
    }
  }

  applySecurity(headers, op.security, securitySchemes, tokens);

  if (op.requestBody) {
    headers["Content-Type"] = op.requestBody.contentType;
  }

  return headers;
}

export function buildBody(
  requestBody?: OpenApiRequestBody,
  overrides?: Record<string, string>,
): string | null {
  if (!requestBody) return null;
  const value = defaultValueForSchema(requestBody.schema, requestBody.example);
  if (overrides && Object.keys(overrides).length > 0) {
    const obj =
      typeof value === "object" && value !== null && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};
    for (const [k, v] of Object.entries(overrides)) {
      obj[k] = v;
    }
    return JSON.stringify(obj);
  }
  return typeof value === "string" ? value : JSON.stringify(value);
}

// --- HTTP sender ---

interface ProxyResponse {
  response: HttpResponse;
}

const HTTP_TIMEOUT_MS = 30_000; // 30-second timeout for each HTTP request

function sendViaProxy(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: string | null,
  proxyPort: number,
): Promise<ProxyResponse> {
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
      timeout: HTTP_TIMEOUT_MS,
    };

    const req = (isHttps ? https : http).request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        const resHeaders: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (typeof value === "string") {
            resHeaders[key] = value;
          } else if (Array.isArray(value)) {
            resHeaders[key] = value.join(", ");
          }
        }
        resolve({
          response: {
            statusCode: res.statusCode ?? 0,
            headers: resHeaders,
            body: chunks.length > 0 ? Buffer.concat(chunks) : null,
          },
        });
      });
      res.on("error", reject);
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`HTTP request timed out after ${HTTP_TIMEOUT_MS}ms: ${method} ${url}`));
    });
    req.on("error", reject);

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

// --- Plugin ---

export default class OpenApiPlugin implements ScenarioPlugin {
  readonly name = "scenario:openapi";

  async init(context: PluginContext): Promise<void> {
    const { commandBus } = context;
    context.commandBus.register(ReplayCommand, async (cmd) => {
      const { scenario, config } = cmd;
      const source = scenario.source as OpenApiScenarioSource;

      await executeSteps(source.steps, config, source.securitySchemes);

      for (const so of source.secondOrders ?? []) {
        await executeSteps(so.steps, config, source.securitySchemes);
      }

      const exchanges = await commandBus.dispatch<Exchange[]>(
        new LoadExchangesCommand(config.replayId),
      );
      if (exchanges.length === 0) {
        throw new Error(
          `No exchange captured for replayId: ${config.replayId}`,
        );
      }
      // 保存順 = 実行順 (main steps → secondOrder steps) により、
      // 先頭が main exchange、残りが secondOrder exchanges となる。
      // この順序契約はここ(ハンドラ)に局所化し、呼び出し側は配列順序を知らなくて済む。
      const [exchange, ...secondOrderExchanges] = exchanges;
      return new ReplayResult(exchange, secondOrderExchanges);
    });
  }
}

async function executeSteps(
  steps: import("../loader/openapi-loader.ts").OpenApiStep[],
  config: import("../../commands/replay.ts").ReplayConfig,
  securitySchemes?: Record<string, OpenApiSecurityScheme>,
): Promise<void> {
  const overridesMap: Record<string, string> = {};
  const bodyOverridesMap: Record<string, string> = {};
  const tokensByScheme: Record<string, string> = {};

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const isLast = i === steps.length - 1;

    const url = buildUrl(step.operation, overridesMap);
    const headers = buildHeaders(
      step.operation,
      config.replayId,
      overridesMap,
      securitySchemes,
      tokensByScheme,
    );
    const body = buildBody(step.operation.requestBody, bodyOverridesMap);

    if (isLast) {
      headers["X-Gevanni-Exchange-Id"] = ExchangeId(randomUUID());
      headers["X-Gevanni-Mutate"] = "true";
    }

    const { response } = await sendViaProxy(
      step.operation.method,
      url,
      headers,
      body,
      config.proxyPort,
    );

    // securitySchemes の x-gevanni-token で token を抽出（token を返す step の response）
    if (securitySchemes) {
      for (const [schemeName, scheme] of Object.entries(securitySchemes)) {
        if (!scheme.tokenExpr) continue;
        const tok = resolveRuntimeExpression(scheme.tokenExpr, response);
        if (tok) tokensByScheme[schemeName] = tok;
      }
    }

    if (step.link) {
      for (const [paramName, expr] of Object.entries(step.link.parameters)) {
        overridesMap[paramName] = resolveRuntimeExpression(expr, response);
      }
      if (step.link.requestBody) {
        for (const [fieldName, expr] of Object.entries(
          step.link.requestBody,
        )) {
          bodyOverridesMap[fieldName] = resolveRuntimeExpression(
            expr,
            response,
          );
        }
      }
    }
  }
}

export { OpenApiScenarioType } from "../loader/openapi-loader.ts";
