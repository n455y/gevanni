import fs from "node:fs";
import crypto from "node:crypto";
import yaml from "js-yaml";
import type { Scenario } from "../../../types/models.ts";
import { ScenarioId } from "../../../types/branded.ts";
import { ScenarioType } from "../../../types/branded.ts";
import type { ScenarioLoaderPlugin, PluginContext } from "../../../core/plugin.ts";
import { isObject } from "./schema.ts";
import { isOpenApi3, extractOperations } from "./parser.ts";
import { buildScenariosFromExtension } from "./builder.ts";

// Re-export everything for backward compatibility
export type {
  OpenApiParameter,
  OpenApiRequestBody,
  OpenApiLink,
  OpenApiOperation,
  OpenApiSecurityScheme,
  OpenApiStep,
  OpenApiSecondOrder,
  OpenApiScenarioSource,
  MatchExpr,
  StepDef,
} from "./types.ts";
export { isObject, mergeAllOf, resolveSchema, expandSchemaVariants, defaultValueForSchema } from "./schema.ts";
export {
  RefResolver,
  isOpenApi3,
  extractSecurity,
  extractSecuritySchemes,
  extractParameters,
  extractRequestBodyVariants,
  extractLinks,
  extractOperations,
} from "./parser.ts";
export { buildScenariosFromExtension } from "./builder.ts";

// --- Helpers ---

function scenarioId(): ScenarioId {
  return ScenarioId(crypto.randomUUID());
}

// --- Loader ---

export const OpenApiScenarioType = ScenarioType("openapi");

export async function loadOpenApiScenarios(source: unknown): Promise<Scenario[]> {
  if (typeof source !== "string") return [];

  let raw: string;
  try {
    raw = fs.readFileSync(source, "utf-8");
  } catch {
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    try {
      parsed = yaml.load(raw);
    } catch {
      return [];
    }
  }

  if (!isOpenApi3(parsed)) return [];

  const operations = extractOperations(parsed);
  const sources = buildScenariosFromExtension(parsed, operations);

  const ext = isObject(parsed) ? parsed["x-gevanni-scenarios"] : undefined;
  const extEntries = Array.isArray(ext) ? ext : [];

  return sources.map((source, i) => {
    const scenarioId_value = extEntries[i]?.id;
    const name =
      typeof scenarioId_value === "string"
        ? scenarioId_value
        : source.steps[0].operation.operationId ??
          source.steps[0].operation.summary ??
          `${source.steps[0].operation.method} ${source.steps[0].operation.path}`;
    const steps = source.steps;
    const lines = [`  ${name}`];
    for (const step of steps) {
      const op = step.operation;
      lines.push(`    ${op.method} ${op.path}${op.operationId ? ` (${op.operationId})` : ""}${op.summary ? ` - ${op.summary}` : ""}`);
      if (op.parameters.length > 0) {
        lines.push(`      params: ${op.parameters.map((p) => p.name).join(", ")}`);
      }
      if (op.requestBody) {
        lines.push(`      body: ${op.requestBody.contentType}`);
      }
    }
    return {
      id: scenarioId(),
      name,
      type: OpenApiScenarioType,
      source,
      representation: lines.join("\n"),
      diffStrategy: source.diff ?? { type: "exact" },
    };
  });
}

// --- Loader plugin ---
// Plugin responsible for loading scenarios (file → Scenario[]).
// Separate responsibility and namespace from the execution side (scenario:openapi, ReplayCommand handler).
// Parsing logic is delegated to the existing loadOpenApiScenarios function; this just wraps it.
export default class OpenApiLoaderPlugin implements ScenarioLoaderPlugin {
  readonly name = "scenario-loader:openapi";

  // loader does not register anything on the commandBus (read-only)
  async init(_context: PluginContext): Promise<void> {}

  async loadScenarios(source: unknown): Promise<Scenario[]> {
    return loadOpenApiScenarios(source);
  }
}
