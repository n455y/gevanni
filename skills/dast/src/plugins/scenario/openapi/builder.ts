import type { DiffStrategyConfig, DiffStrategyType } from "../../../types/models.ts";
import type {
  OpenApiOperation,
  OpenApiRequestBody,
  OpenApiScenarioSource,
  OpenApiLink,
  OpenApiStep,
  OpenApiSecondOrder,
  MatchExpr,
  StepDef,
} from "./types.ts";
import { isObject } from "./schema.ts";
import { extractSecuritySchemes } from "./parser.ts";

// --- Diff config parsing ---

const KNOWN_DIFF_STRATEGIES = new Set<DiffStrategyType>([
  "exact",
  "json",
  "html",
]);

function parseDiffConfig(
  raw: unknown,
  context: string,
): DiffStrategyConfig | undefined {
  if (raw === undefined) return undefined;
  if (!isObject(raw)) {
    throw new Error(
      `${context}: invalid diff config (expected an object, got ${typeof raw})`,
    );
  }
  const strategy = raw.strategy;
  if (typeof strategy !== "string") {
    throw new Error(
      `${context}: diff.strategy must be a string`,
    );
  }
  if (!KNOWN_DIFF_STRATEGIES.has(strategy as DiffStrategyType)) {
    throw new Error(
      `${context}: unknown diff strategy "${strategy}". Known strategies: ${[...KNOWN_DIFF_STRATEGIES].join(", ")}`,
    );
  }
  const options = isObject(raw.options)
    ? (raw.options as Record<string, unknown>)
    : undefined;
  return { type: strategy as DiffStrategyType, options };
}

// --- Step definition parsing ---

function parseStepDefs(raw: unknown): StepDef[] {
  if (!Array.isArray(raw)) return [];
  const defs: StepDef[] = [];
  for (const entry of raw) {
    if (typeof entry === "string") {
      defs.push({ ref: entry });
    } else if (isObject(entry)) {
      const ref = entry.id ?? entry.operationId;
      if (typeof ref !== "string") continue;
      const match = entry.match;
      defs.push({
        ref,
        match:
          typeof match === "number" || isObject(match) || Array.isArray(match)
            ? (match as MatchExpr)
            : undefined,
      });
    }
  }
  return defs;
}

function expandStepDefs(
  defs: StepDef[],
  scenarioDefs: Map<string, StepDef[]>,
  byId: Map<string, OpenApiOperation>,
  depth = 0,
): StepDef[] {
  if (depth > 10) return defs;
  const expanded: StepDef[] = [];
  for (const def of defs) {
    if (!byId.has(def.ref) && scenarioDefs.has(def.ref)) {
      const inner = expandStepDefs(
        scenarioDefs.get(def.ref)!,
        scenarioDefs,
        byId,
        depth + 1,
      );
      expanded.push(...inner);
    } else {
      expanded.push(def);
    }
  }
  return expanded;
}

// --- Match resolution ---

function matchesVariant(
  schema: Record<string, unknown> | undefined,
  criterion: Record<string, unknown>,
): boolean {
  if (!schema || !isObject(schema.properties)) return false;
  for (const [key, value] of Object.entries(criterion)) {
    const prop = schema.properties[key];
    if (!isObject(prop)) return false;
    if (isObject(value)) {
      const innerVariants = prop.oneOf;
      if (!Array.isArray(innerVariants)) return false;
      if (!innerVariants.some((v) => {
        const d = isObject(v) ? v : undefined;
        return d && matchesVariant(d as Record<string, unknown>, value);
      })) return false;
    } else {
      if (Array.isArray(prop.enum) && !prop.enum.includes(value)) return false;
      if (prop.const !== undefined && prop.const !== value) return false;
      if (!Array.isArray(prop.enum) && prop.const === undefined) return false;
    }
  }
  return true;
}

function mergeRequestBodyVariants(variants: OpenApiRequestBody[]): OpenApiRequestBody {
  if (variants.length === 0) throw new Error("No variants to merge");
  const merged = { ...variants[0] };
  const mergedProps: Record<string, unknown> = {};
  for (const v of variants) {
    if (v.schema?.properties && isObject(v.schema.properties)) {
      Object.assign(mergedProps, v.schema.properties);
    }
  }
  if (Object.keys(mergedProps).length > 0) {
    merged.schema = { ...merged.schema, type: "object", properties: mergedProps };
  }
  return merged;
}

function resolveMatch(
  variants: OpenApiRequestBody[],
  match: MatchExpr,
): OpenApiRequestBody | undefined {
  if (typeof match === "number") {
    return variants[match];
  }

  const criteria = Array.isArray(match) ? match : [match];
  const matched: OpenApiRequestBody[] = [];

  for (const c of criteria) {
    const found = variants.find((v) =>
      matchesVariant(v.schema as Record<string, unknown> | undefined, c),
    );
    if (found) matched.push(found);
  }

  if (matched.length === 0) return undefined;
  if (matched.length === 1) return matched[0];
  return mergeRequestBodyVariants(matched);
}

function resolveStepDefs(
  defs: StepDef[],
  byId: Map<string, OpenApiOperation>,
): OpenApiStep[] {
  const steps: OpenApiStep[] = [];
  for (let i = 0; i < defs.length; i++) {
    const op = byId.get(defs[i].ref);
    if (!op) continue;

    let resolvedOp = op;
    const stepMatch = defs[i].match;
    if (stepMatch !== undefined && op.bodyVariants) {
      const resolved = resolveMatch(op.bodyVariants, stepMatch);
      if (resolved) {
        resolvedOp = { ...op, requestBody: resolved };
      }
    }

    const link: OpenApiLink | undefined =
      i < defs.length - 1
        ? resolvedOp.links?.find((l) => l.targetOperationId === defs[i + 1].ref)
        : undefined;
    steps.push({
      operation: resolvedOp,
      link,
    });
  }
  return steps;
}

// --- Public API ---

export function buildScenariosFromExtension(
  doc: unknown,
  operations: OpenApiOperation[],
): OpenApiScenarioSource[] {
  if (!isObject(doc)) return [];
  const ext = doc["x-gevanni-scenarios"];
  if (!Array.isArray(ext)) return [];

  const securitySchemes = extractSecuritySchemes(doc as { openapi?: string });

  const byId = new Map<string, OpenApiOperation>();
  for (const op of operations) {
    if (op.operationId) byId.set(op.operationId, op);
  }

  const scenarioDefs = new Map<string, StepDef[]>();
  for (const entry of ext) {
    if (!isObject(entry)) continue;
    const id = entry.id;
    if (typeof id !== "string") continue;
    const defs = parseStepDefs(entry.steps);
    if (defs.length > 0) scenarioDefs.set(id, defs);
  }

  const sources: OpenApiScenarioSource[] = [];
  for (const entry of ext) {
    if (!isObject(entry)) continue;
    const defs = parseStepDefs(entry.steps);
    if (defs.length === 0) continue;

    const expanded = expandStepDefs(defs, scenarioDefs, byId);
    const steps = resolveStepDefs(expanded, byId);
    if (steps.length === 0) continue;

    const scannable = typeof entry.scannable === "boolean" ? entry.scannable : true;
    if (!scannable) continue;

    const scenarioName = typeof entry.id === "string" ? entry.id : "(unnamed scenario)";
    const diff = parseDiffConfig(entry.diff, `scenario "${scenarioName}"`);

    const secondOrders: OpenApiSecondOrder[] = [];
    if (Array.isArray(entry.secondOrders)) {
      for (const so of entry.secondOrders) {
        if (!isObject(so) || !Array.isArray(so.steps)) continue;
        const soDefs = parseStepDefs(so.steps);
        const soExpanded = expandStepDefs(soDefs, scenarioDefs, byId);
        const soSteps = resolveStepDefs(soExpanded, byId);
        if (soSteps.length > 0) secondOrders.push({ steps: soSteps });
      }
    }

    sources.push({
      steps,
      scannable,
      diff,
      secondOrders: secondOrders.length > 0 ? secondOrders : undefined,
      securitySchemes,
    });
  }

  return sources;
}
