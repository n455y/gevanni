import fs from "node:fs";
import crypto from "node:crypto";
import yaml from "js-yaml";
import type { DiffStrategyConfig, DiffStrategyType, Scenario } from "../../types/models.ts";
import { ScenarioId } from "../../types/branded.ts";
import { ScenarioType } from "../../types/branded.ts";

// --- OpenAPI 3.x types (subset) ---

export interface OpenApiParameter {
  name: string;
  in: "query" | "header" | "path" | "cookie";
  required?: boolean;
  schema?: { type?: string; [key: string]: unknown };
  example?: unknown;
}

export interface OpenApiRequestBody {
  contentType: string;
  schema?: { type?: string; [key: string]: unknown };
  example?: unknown;
}

export interface OpenApiLink {
  targetOperationId: string;
  parameters: Record<string, string>;
  requestBody?: Record<string, string>;
}

export interface OpenApiOperation {
  baseUrl: string;
  method: string;
  path: string;
  operationId?: string;
  summary?: string;
  parameters: OpenApiParameter[];
  requestBody?: OpenApiRequestBody;
  bodyVariants?: OpenApiRequestBody[];
  links?: OpenApiLink[];
}

export interface OpenApiStep {
  operation: OpenApiOperation;
  link?: OpenApiLink;
}

export interface OpenApiSecondOrder {
  steps: OpenApiStep[];
}

export interface OpenApiScenarioSource {
  steps: OpenApiStep[];
  scannable: boolean;
  diff?: DiffStrategyConfig;
  secondOrders?: OpenApiSecondOrder[];
}

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

// --- Helpers ---

function scenarioId(): ScenarioId {
  return ScenarioId(crypto.randomUUID());
}

const HTTP_METHODS = [
  "get",
  "put",
  "post",
  "delete",
  "options",
  "head",
  "patch",
  "trace",
] as const;

function mergeAllOf(schemas: unknown[]): Record<string, unknown> {
  const allProperties: Record<string, unknown> = {};
  const allRequired: string[] = [];
  const extra: Record<string, unknown> = { type: "object" };

  for (const s of schemas) {
    if (!isObject(s)) continue;
    if (isObject(s.properties)) {
      Object.assign(allProperties, s.properties);
    }
    if (Array.isArray(s.required)) {
      allRequired.push(...(s.required as string[]));
    }
    for (const [k, v] of Object.entries(s)) {
      if (k !== "properties" && k !== "required" && k !== "allOf") {
        extra[k] = v;
      }
    }
  }

  if (Object.keys(allProperties).length > 0) extra.properties = allProperties;
  if (allRequired.length > 0) extra.required = [...new Set(allRequired)];
  return extra;
}

function resolveSchema(schema: unknown): Record<string, unknown> | undefined {
  if (!isObject(schema)) return undefined;
  if (Array.isArray(schema.allOf)) return mergeAllOf(schema.allOf);
  return { ...schema };
}

function expandSchemaVariants(schema: unknown, resolver: RefResolver): Record<string, unknown>[] {
  const deref = resolver.resolve<Record<string, unknown>>(schema);
  if (!deref) return [{}];
  const resolved = resolveSchema(deref);
  if (!resolved) return [{}];
  const variants = resolved.oneOf;
  if (!Array.isArray(variants)) return [resolved];
  return variants
    .map((v) => {
      const d = resolver.resolve<Record<string, unknown>>(v);
      return d ? resolveSchema(d) : undefined;
    })
    .filter((v): v is Record<string, unknown> => v !== undefined);
}

export function defaultValueForSchema(
  schema?: { type?: string; [key: string]: unknown },
  example?: unknown,
): unknown {
  if (example !== undefined) return example;
  if (!schema) return "test";

  if (schema.default !== undefined) return schema.default;
  if (Array.isArray(schema.enum) && schema.enum.length > 0) return schema.enum[0];

  if (Array.isArray(schema.allOf)) {
    return defaultValueForSchema(mergeAllOf(schema.allOf));
  }

  if (Array.isArray(schema.oneOf)) {
    const variants = schema.oneOf as unknown[];
    const first = variants[0];
    return first ? defaultValueForSchema(first as { type?: string; [key: string]: unknown }) : "test";
  }

  switch (schema.type) {
    case "integer":
    case "number":
      return 1;
    case "boolean":
      return true;
    case "array":
      return [];
    case "object": {
      if (isObject(schema.properties)) {
        const obj: Record<string, unknown> = {};
        for (const [key, propSchema] of Object.entries(schema.properties)) {
          obj[key] = defaultValueForSchema(
            propSchema as { type?: string; [key: string]: unknown },
          );
        }
        return obj;
      }
      return {};
    }
    default:
      return "test";
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// --- $ref resolver ---

class RefResolver {
  private doc: Record<string, unknown>;
  constructor(doc: unknown) {
    this.doc = (doc ?? {}) as Record<string, unknown>;
  }

  resolve<T>(node: unknown, depth = 0): T | undefined {
    if (depth > 10) return undefined;
    if (!isObject(node)) return undefined;
    if ("$ref" in node && typeof node.$ref === "string") {
      const target = this.followPointer(node.$ref);
      return target ? this.resolve<T>(target, depth + 1) : undefined;
    }
    return node as T;
  }

  private followPointer(pointer: string): unknown {
    if (!pointer.startsWith("#/")) return undefined;
    const parts = pointer.slice(2).split("/");
    let current: unknown = this.doc;
    for (const part of parts) {
      if (!isObject(current)) return undefined;
      current = current[part];
    }
    return current;
  }
}

interface OpenApiDoc {
  openapi?: string;
  servers?: { url: string }[];
  paths?: Record<string, Record<string, unknown>>;
  components?: Record<string, unknown>;
}

function isOpenApi3(data: unknown): data is OpenApiDoc {
  if (!isObject(data)) return false;
  return typeof data.openapi === "string" && data.openapi.startsWith("3.");
}

function extractParameters(rawList: unknown, resolver: RefResolver): OpenApiParameter[] {
  const params: OpenApiParameter[] = [];
  if (!Array.isArray(rawList)) return params;
  for (const p of rawList) {
    const deref = resolver.resolve<Record<string, unknown>>(p);
    if (!deref) continue;
    params.push({
      name: deref.name as string,
      in: deref.in as OpenApiParameter["in"],
      required: deref.required as boolean | undefined,
      schema: deref.schema as OpenApiParameter["schema"],
      example: deref.example,
    });
  }
  return params;
}

function extractRequestBodyVariants(
  opBody: unknown,
  resolver: RefResolver,
): OpenApiRequestBody[] {
  const deref = resolver.resolve<Record<string, unknown>>(opBody);
  if (!deref) return [];
  const content = deref.content as Record<string, unknown> | undefined;
  if (!isObject(content)) return [];
  const ct = Object.keys(content)[0];
  const mediaType = content[ct] as Record<string, unknown>;
  const rawSchema = mediaType?.schema;
  if (!isObject(rawSchema)) return [];

  const variants = expandSchemaVariants(rawSchema, resolver);
  return variants.map((s) => ({
    contentType: ct,
    schema: s as OpenApiRequestBody["schema"],
    example: mediaType.example,
  }));
}

function extractLinks(responses: unknown): OpenApiLink[] {
  const links: OpenApiLink[] = [];
  if (!isObject(responses)) return links;

  for (const response of Object.values(responses)) {
    if (!isObject(response)) continue;
    const linkMap = response.links;
    if (!isObject(linkMap)) continue;

    for (const linkDef of Object.values(linkMap)) {
      if (!isObject(linkDef)) continue;
      if ("operationRef" in linkDef && !("operationId" in linkDef)) continue;
      if (!("operationId" in linkDef)) continue;

      const params: Record<string, string> = {};
      if (isObject(linkDef.parameters)) {
        for (const [k, v] of Object.entries(linkDef.parameters)) {
          if (typeof v === "string") params[k] = v;
        }
      }

      let reqBody: Record<string, string> | undefined;
      if (isObject(linkDef.requestBody)) {
        reqBody = {};
        for (const [k, v] of Object.entries(linkDef.requestBody)) {
          if (typeof v === "string") reqBody[k] = v;
        }
      }

      links.push({
        targetOperationId: linkDef.operationId as string,
        parameters: params,
        requestBody: reqBody,
      });
    }
  }

  return links;
}

function extractOperations(doc: OpenApiDoc): OpenApiOperation[] {
  const baseUrl = doc.servers?.[0]?.url ?? "http://localhost";
  const resolver = new RefResolver(doc);
  const operations: OpenApiOperation[] = [];

  for (const [path, pathItem] of Object.entries(doc.paths ?? {})) {
    if (!isObject(pathItem)) continue;

    const pathLevelParams = extractParameters(pathItem.parameters, resolver);

    for (const method of HTTP_METHODS) {
      const operation = pathItem[method];
      if (!isObject(operation)) continue;

      const opParams = extractParameters(operation.parameters, resolver);
      const parameters = [...pathLevelParams, ...opParams];
      const bodyVariants = extractRequestBodyVariants(operation.requestBody, resolver);
      const links = extractLinks(operation.responses);
      const operationId = operation.operationId as string | undefined;

      const base = {
        baseUrl,
        method: method.toUpperCase(),
        path,
        operationId,
        summary: operation.summary as string | undefined,
        parameters,
        links: links.length > 0 ? links : undefined,
      };

      operations.push({
        ...base,
        requestBody: bodyVariants[0],
        bodyVariants: bodyVariants.length > 1 ? bodyVariants : undefined,
      });
    }
  }

  return operations;
}

// --- Scenario building from x-gevanni-scenarios ---

export type MatchExpr = Record<string, unknown> | Record<string, unknown>[] | number;

interface StepDef {
  ref: string;
  match?: MatchExpr;
}

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

export function buildScenariosFromExtension(
  doc: unknown,
  operations: OpenApiOperation[],
): OpenApiScenarioSource[] {
  if (!isObject(doc)) return [];
  const ext = doc["x-gevanni-scenarios"];
  if (!Array.isArray(ext)) return [];

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
    });
  }

  return sources;
}

export { extractOperations, isOpenApi3 };

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
