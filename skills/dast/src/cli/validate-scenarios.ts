/**
 * validate-scenarios — 生成されたシナリオの遷移を実際のHTTPリクエストで検証する。
 *
 * CLI から `gevanni validate-scenarios <spec.yaml>` で実行する。
 *
 * 各シナリオのステップを順に実HTTPリクエストし、
 * - リクエスト構築の成否
 * - サーバー応答の有無
 * - ステップ間のLink解決の成否
 * を検証してレポートする。
 */

import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import {
  loadOpenApiScenarios,
} from "../plugins/loader/openapi-loader.ts";
import {
  buildUrl,
  buildHeaders,
  buildBody,
  resolveRuntimeExpression,
} from "../plugins/scenario/openapi.ts";
import type { ReplayId } from "../types/branded.ts";

// --- HTTP sender (direct, no proxy needed for validation) ---
interface SimpleResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Buffer | null;
}

const HTTP_TIMEOUT_MS = 15_000;

function sendHttpRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: string | null,
): Promise<SimpleResponse> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === "https:";

    const options: https.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers,
      rejectUnauthorized: false,
      timeout: HTTP_TIMEOUT_MS,
    };

    const req = (isHttps ? https : http).request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        const resHeaders: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (typeof value === "string") resHeaders[key] = value;
          else if (Array.isArray(value)) resHeaders[key] = value.join(", ");
        }
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: resHeaders,
          body: chunks.length > 0 ? Buffer.concat(chunks) : null,
        });
      });
      res.on("error", reject);
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`HTTP timeout after ${HTTP_TIMEOUT_MS}ms`));
    });
    req.on("error", reject);

    if (body) req.write(body);
    req.end();
  });
}

// --- Step execution ---
interface StepResult {
  operationId: string;
  method: string;
  path: string;
  url: string;
  statusCode: number;
  success: boolean;
  error?: string;
  linkResults: LinkResult[];
}

interface LinkResult {
  targetOperationId: string;
  paramName: string;
  expression: string;
  resolved: boolean;
  resolvedValue?: string;
  error?: string;
}

interface ScenarioResult {
  scenarioId: string;
  steps: StepResult[];
  allTransitionsValid: boolean;
}

async function executeScenarioSteps(
  source: Awaited<ReturnType<typeof loadOpenApiScenarios>>[number],
): Promise<ScenarioResult> {
  const src = source.source as {
    steps: Array<{
      operation: {
        operationId?: string;
        method: string;
        path: string;
        baseUrl: string;
        parameters: Array<{ name: string; in: string; schema?: object; example?: unknown }>;
        requestBody?: { contentType: string; schema?: object; example?: unknown };
        links?: Array<{
          targetOperationId: string;
          parameters: Record<string, string>;
          requestBody?: Record<string, string>;
        }>;
        security?: string[];
      };
      link?: {
        targetOperationId: string;
        parameters: Record<string, string>;
        requestBody?: Record<string, string>;
      };
    }>;
    securitySchemes?: Record<string, {
      type: string;
      scheme?: string;
      in?: string;
      name?: string;
      tokenExpr?: string;
    }>;
  };

  const stepResults: StepResult[] = [];
  const overridesMap: Record<string, string> = {};
  const bodyOverridesMap: Record<string, string> = {};
  const tokensByScheme: Record<string, string> = {};

  for (let i = 0; i < src.steps.length; i++) {
    const step = src.steps[i];
    const op = step.operation;

    let url: string;
    try {
      url = buildUrl(op as Parameters<typeof buildUrl>[0], overridesMap);
    } catch (err) {
      stepResults.push({
        operationId: op.operationId ?? `${op.method} ${op.path}`,
        method: op.method,
        path: op.path,
        url: `${op.baseUrl}${op.path}`,
        statusCode: 0,
        success: false,
        error: `URL build failed: ${err instanceof Error ? err.message : String(err)}`,
        linkResults: [],
      });
      continue;
    }

    let headers: Record<string, string>;
    try {
      headers = buildHeaders(
        op as Parameters<typeof buildHeaders>[0],
        "validate" as unknown as ReplayId,
        overridesMap,
        src.securitySchemes as Parameters<typeof buildHeaders>[3],
        tokensByScheme,
      );
    } catch (err) {
      stepResults.push({
        operationId: op.operationId ?? `${op.method} ${op.path}`,
        method: op.method,
        path: op.path,
        url,
        statusCode: 0,
        success: false,
        error: `Header build failed: ${err instanceof Error ? err.message : String(err)}`,
        linkResults: [],
      });
      continue;
    }

    let body: string | null = null;
    try {
      body = buildBody(op.requestBody as Parameters<typeof buildBody>[0], bodyOverridesMap);
    } catch (err) {
      stepResults.push({
        operationId: op.operationId ?? `${op.method} ${op.path}`,
        method: op.method,
        path: op.path,
        url,
        statusCode: 0,
        success: false,
        error: `Body build failed: ${err instanceof Error ? err.message : String(err)}`,
        linkResults: [],
      });
      continue;
    }

    // --- Send the request ---
    let response: SimpleResponse;
    try {
      response = await sendHttpRequest(op.method, url, headers, body);
    } catch (err) {
      stepResults.push({
        operationId: op.operationId ?? `${op.method} ${op.path}`,
        method: op.method,
        path: op.path,
        url,
        statusCode: 0,
        success: false,
        error: `HTTP request failed: ${err instanceof Error ? err.message : String(err)}`,
        linkResults: [],
      });
      continue;
    }

    // --- Verify Link resolution ---
    const linkResults: LinkResult[] = [];
    if (step.link) {
      for (const [paramName, expr] of Object.entries(step.link.parameters)) {
        const resolved = resolveRuntimeExpression(expr, {
          statusCode: response.statusCode,
          headers: response.headers,
          body: response.body,
        });
        linkResults.push({
          targetOperationId: step.link.targetOperationId,
          paramName,
          expression: expr,
          resolved: resolved !== "" && resolved !== undefined,
          resolvedValue: resolved || undefined,
          error: resolved === "" ? `Expression "${expr}" resolved to empty string` : undefined,
        });
      }
    }

    // Token extraction
    if (src.securitySchemes) {
      const httpResponse = {
        statusCode: response.statusCode,
        headers: response.headers,
        body: response.body,
      };
      for (const [schemeName, scheme] of Object.entries(src.securitySchemes)) {
        if (!scheme.tokenExpr) continue;
        const tok = resolveRuntimeExpression(scheme.tokenExpr, httpResponse);
        if (tok) tokensByScheme[schemeName] = tok;
      }
    }

    // Populate overrides for next step
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

    stepResults.push({
      operationId: op.operationId ?? `${op.method} ${op.path}`,
      method: op.method,
      path: op.path,
      url,
      statusCode: response.statusCode,
      success: true,
      linkResults,
    });
  }

  const allValid = stepResults.every((s) => s.success) &&
    stepResults.every((s) => s.linkResults.every((l) => l.resolved));

  return {
    scenarioId: source.name,
    steps: stepResults,
    allTransitionsValid: allValid,
  };
}

// --- Main entry point ---
export interface ValidateScenariosOptions {
  baseUrl?: string;
}

export async function validateScenarios(
  specPath: string,
  opts: ValidateScenariosOptions = {},
): Promise<{ allPassed: boolean; results: ScenarioResult[] }> {
  const absSpec = path.resolve(specPath);
  if (!fs.existsSync(absSpec)) {
    throw new Error(`Spec file not found: ${absSpec}`);
  }

  console.log("🔗 Validating scenario transitions...\n");
  console.log(`📄 Spec: ${absSpec}`);
  if (opts.baseUrl) {
    console.log(`🌐 Base URL override: ${opts.baseUrl}`);
  }
  console.log("");

  const scenarios = await loadOpenApiScenarios(absSpec);

  if (scenarios.length === 0) {
    console.log("⚠️  No scenarios found in spec.");
    return { allPassed: true, results: [] };
  }

  console.log(`📋 Found ${scenarios.length} scenario(s)\n`);

  const results: ScenarioResult[] = [];
  for (const scenario of scenarios) {
    console.log(`▶ Running: ${scenario.name}`);
    const result = await executeScenarioSteps(scenario);
    results.push(result);

    for (const step of result.steps) {
      if (step.success) {
        console.log(`  ✅ ${step.method} ${step.path} → ${step.statusCode}`);
        for (const link of step.linkResults) {
          if (link.resolved) {
            console.log(`     🔗 Link → ${link.targetOperationId}.${link.paramName}: ${link.resolvedValue?.substring(0, 50)}`);
          } else {
            console.log(`     ⚠️  Link → ${link.targetOperationId}.${link.paramName}: ${link.error}`);
          }
        }
      } else {
        console.log(`  ❌ ${step.method} ${step.path}: ${step.error}`);
      }
    }
    console.log("");
  }

  // --- Summary ---
  const totalSteps = results.reduce((sum, r) => sum + r.steps.length, 0);
  const passedSteps = results.reduce((sum, r) => sum + r.steps.filter((s) => s.success).length, 0);
  const totalLinks = results.reduce(
    (sum, r) => sum + r.steps.reduce((s, step) => s + step.linkResults.length, 0),
    0,
  );
  const resolvedLinks = results.reduce(
    (sum, r) =>
      sum +
      r.steps.reduce((s, step) => s + step.linkResults.filter((l) => l.resolved).length, 0),
    0,
  );
  const allPassed = results.every((r) => r.allTransitionsValid);

  console.log("═══════════════════════════════════════");
  console.log("🔗 Scenario transition integrity:");
  console.log(`   • Scenarios checked:     ${results.length}`);
  console.log(`   • Multi-step scenarios:  ${results.filter((r) => r.steps.length > 1).length}`);
  console.log(`   • Total step executions: ${totalSteps}`);
  console.log(`   • ✅ Successful steps:   ${passedSteps}`);
  console.log(`   • ❌ Failed steps:       ${totalSteps - passedSteps}`);
  console.log(`   • 🔗 Links checked:      ${totalLinks}`);
  console.log(`   • ✅ Resolved links:     ${resolvedLinks}`);
  console.log(`   • ⚠️  Unresolved links:   ${totalLinks - resolvedLinks}`);
  console.log("═══════════════════════════════════════");

  if (allPassed) {
    console.log("\n✅ All scenario transitions are valid.");
  } else {
    console.log("\n❌ Some transitions failed. Review the errors above.");
  }

  return { allPassed, results };
}
