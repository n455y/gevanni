import { type Exchange, type HttpResponse, ReplayResult } from "../../../types/models.ts";
import { ExchangeId } from "../../../types/branded.ts";
import type { ReplayId } from "../../../types/branded.ts";
import type {
  ScenarioPlugin,
  PluginContext,
  ScenarioValidationResult,
  ScenarioValidationStepResult,
  ScenarioValidationTransitionResult,
  ValidateScenarioOptions,
} from "../../../core/plugin.ts";
import type { Scenario } from "../../../types/models.ts";
import { sendHttpRequest } from "../../../http/sender.ts";
import { ReplayCommand } from "../../../commands/replay.ts";
import type { ReplayConfig } from "../../../commands/replay.ts";
import { LoadExchangesCommand } from "../../../commands/exchange.ts";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import http from "node:http";
import https from "node:https";
import { randomUUID } from "node:crypto";
import type {
  OpenApiScenarioSource,
  OpenApiSecurityScheme,
  OpenApiStep,
} from "./types.ts";

// Re-export for backward compatibility
export { resolveRuntimeExpression } from "./runtime-expression.ts";
export {
  buildUrl,
  applySecurity,
  buildHeaders,
  buildBody,
} from "./request-builder.ts";
export { OpenApiScenarioType } from "./loader.ts";

// Import locally for internal use (already imported from request-builder via re-export)
import { buildUrl, buildHeaders, buildBody } from "./request-builder.ts";
import { resolveRuntimeExpression } from "./runtime-expression.ts";

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

    let settled = false;
    const req = (isHttps ? https : http).request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        if (settled) return;
        settled = true;
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
      res.on("error", (err) => {
        if (settled) return;
        settled = true;
        reject(err);
      });
    });

    req.on("timeout", () => {
      if (settled) return;
      settled = true;
      req.destroy();
      reject(new Error(`HTTP request timed out after ${HTTP_TIMEOUT_MS}ms: ${method} ${url}`));
    });
    req.on("error", (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });

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
      // Storage order = execution order (main steps → secondOrder steps), so
      // the first is the main exchange, the rest are secondOrder exchanges.
      // This ordering contract is localized here (in the handler); callers don't need to know the array order.
      const [exchange, ...secondOrderExchanges] = exchanges;
      return new ReplayResult(exchange, secondOrderExchanges);
    });
  }

  async validateScenario(
    scenario: Scenario,
    options?: ValidateScenarioOptions,
  ): Promise<ScenarioValidationResult> {
    const source = scenario.source as OpenApiScenarioSource;
    const steps = await executeValidationSteps(
      source.steps,
      source.securitySchemes,
      options?.upstreamProxyUrl,
    );
    const allValid = steps.every((s) => s.success) &&
      steps.every((s) => s.transitions.every((t) => t.resolved));
    return {
      scenarioName: scenario.name,
      allValid,
      steps,
    };
  }
}

async function executeSteps(
  steps: OpenApiStep[],
  config: ReplayConfig,
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

    // Extract token via x-gevanni-token in securitySchemes (from the response of the token-returning step)
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

async function executeValidationSteps(
  steps: OpenApiStep[],
  securitySchemes?: Record<string, OpenApiSecurityScheme>,
  upstreamProxyUrl?: string,
): Promise<ScenarioValidationStepResult[]> {
  const overridesMap: Record<string, string> = {};
  const bodyOverridesMap: Record<string, string> = {};
  const tokensByScheme: Record<string, string> = {};
  const results: ScenarioValidationStepResult[] = [];

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const op = step.operation;
    const stepId = op.operationId ?? `${op.method} ${op.path}`;

    // --- Build URL ---
    let url: string;
    try {
      url = buildUrl(op, overridesMap);
    } catch (err) {
      results.push({
        stepId,
        description: `${op.method} ${op.path}`,
        method: op.method,
        url: `${op.baseUrl}${op.path}`,
        statusCode: 0,
        success: false,
        error: `URL build failed: ${err instanceof Error ? err.message : String(err)}`,
        transitions: [],
      });
      continue;
    }

    // --- Build Headers ---
    let headers: Record<string, string>;
    try {
      headers = buildHeaders(
        op,
        "validate" as unknown as ReplayId,
        overridesMap,
        securitySchemes,
        tokensByScheme,
      );
    } catch (err) {
      results.push({
        stepId,
        description: `${op.method} ${op.path}`,
        method: op.method,
        url,
        statusCode: 0,
        success: false,
        error: `Header build failed: ${err instanceof Error ? err.message : String(err)}`,
        transitions: [],
      });
      continue;
    }

    // --- Build Body ---
    let body: string | null = null;
    try {
      body = buildBody(op.requestBody, bodyOverridesMap);
    } catch (err) {
      results.push({
        stepId,
        description: `${op.method} ${op.path}`,
        method: op.method,
        url,
        statusCode: 0,
        success: false,
        error: `Body build failed: ${err instanceof Error ? err.message : String(err)}`,
        transitions: [],
      });
      continue;
    }

    // --- Send HTTP request ---
    let response: { statusCode: number; headers: Record<string, string>; body: Buffer | null };
    try {
      response = await sendHttpRequest(op.method, url, headers, body, upstreamProxyUrl);
    } catch (err) {
      results.push({
        stepId,
        description: `${op.method} ${op.path}`,
        method: op.method,
        url,
        statusCode: 0,
        success: false,
        error: `HTTP request failed: ${err instanceof Error ? err.message : String(err)}`,
        transitions: [],
      });
      continue;
    }

    // --- Resolve transitions (links) ---
    const transitions: ScenarioValidationTransitionResult[] = [];
    if (step.link) {
      for (const [paramName, expr] of Object.entries(step.link.parameters)) {
        const resolved = resolveRuntimeExpression(expr, {
          statusCode: response.statusCode,
          headers: response.headers,
          body: response.body,
        });
        transitions.push({
          description: `${step.link.targetOperationId}.${paramName}`,
          resolved: resolved !== "" && resolved !== undefined,
          resolvedValue: resolved || undefined,
          error: resolved === "" ? `Expression "${expr}" resolved to empty string` : undefined,
        });
      }
    }

    // --- Extract security tokens ---
    if (securitySchemes) {
      const httpResponse = {
        statusCode: response.statusCode,
        headers: response.headers,
        body: response.body,
      };
      for (const [schemeName, scheme] of Object.entries(securitySchemes)) {
        if (!scheme.tokenExpr) continue;
        const tok = resolveRuntimeExpression(scheme.tokenExpr, httpResponse);
        if (tok) tokensByScheme[schemeName] = tok;
      }
    }

    // --- Populate overrides for next step ---
    if (step.link) {
      for (const [paramName, expr] of Object.entries(step.link.parameters)) {
        const resolved = resolveRuntimeExpression(expr, {
          statusCode: response.statusCode,
          headers: response.headers,
          body: response.body,
        });
        if (resolved) overridesMap[paramName] = resolved;
      }
      if (step.link.requestBody) {
        for (const [fieldName, expr] of Object.entries(step.link.requestBody)) {
          const resolved = resolveRuntimeExpression(expr, {
            statusCode: response.statusCode,
            headers: response.headers,
            body: response.body,
          });
          if (resolved) bodyOverridesMap[fieldName] = resolved;
        }
      }
    }

    results.push({
      stepId,
      description: `${op.method} ${op.path}`,
      method: op.method,
      url,
      statusCode: response.statusCode,
      success: true,
      transitions,
    });
  }

  return results;
}
