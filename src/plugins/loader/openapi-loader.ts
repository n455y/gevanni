import fs from "node:fs";
import crypto from "node:crypto";
import yaml from "js-yaml";
import type { Scenario } from "../../types/models.ts";
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
  links?: OpenApiLink[];
}

export interface OpenApiStep {
  operation: OpenApiOperation;
  link?: OpenApiLink;
  secondOrders?: OpenApiSecondOrder[];
  scannable: boolean;
}

export interface OpenApiSecondOrder {
  steps: OpenApiStep[];
}

export interface OpenApiScenarioSource {
  steps: OpenApiStep[];
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
  const variants = resolved.oneOf ?? resolved.anyOf;
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

  if (Array.isArray(schema.oneOf) || Array.isArray(schema.anyOf)) {
    const variants = (schema.oneOf ?? schema.anyOf) as unknown[];
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

      const base = {
        baseUrl,
        method: method.toUpperCase(),
        path,
        operationId: operation.operationId as string | undefined,
        summary: operation.summary as string | undefined,
        parameters,
        links: links.length > 0 ? links : undefined,
      };

      if (bodyVariants.length <= 1) {
        operations.push({ ...base, requestBody: bodyVariants[0] });
      } else {
        for (let vi = 0; vi < bodyVariants.length; vi++) {
          operations.push({
            ...base,
            requestBody: bodyVariants[vi],
            operationId: base.operationId
              ? `${base.operationId}_variant${vi + 1}`
              : undefined,
            summary: base.summary
              ? `${base.summary} (variant ${vi + 1})`
              : undefined,
          });
        }
      }
    }
  }

  return operations;
}

// --- Scenario building from x-gevanni-scenarios ---

interface StepDef {
  ref: string;
  secondOrders?: { steps: string[] }[];
  scannable?: boolean;
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
      const secondOrders: { steps: string[] }[] = [];
      if (Array.isArray(entry.secondOrders)) {
        for (const so of entry.secondOrders) {
          if (isObject(so) && Array.isArray(so.steps)) {
            secondOrders.push({
              steps: so.steps.filter((s): s is string => typeof s === "string"),
            });
          }
        }
      }
      defs.push({
        ref,
        secondOrders: secondOrders.length > 0 ? secondOrders : undefined,
        scannable: typeof entry.scannable === "boolean" ? entry.scannable : undefined,
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
      if (def.secondOrders) {
        throw new Error(
          `secondOrders cannot be attached to scenario reference "${def.ref}". Attach secondOrders to an operationId step instead.`,
        );
      }
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
  scenarioDefs: Map<string, StepDef[]>,
  byId: Map<string, OpenApiOperation>,
): OpenApiStep[] {
  const steps: OpenApiStep[] = [];
  for (let i = 0; i < defs.length; i++) {
    const op = byId.get(defs[i].ref);
    if (!op) continue;
    const link: OpenApiLink | undefined =
      i < defs.length - 1
        ? op.links?.find((l) => l.targetOperationId === defs[i + 1].ref)
        : undefined;
    const secondOrders: OpenApiSecondOrder[] = [];
    const soRaw = defs[i].secondOrders;
    if (soRaw) {
      for (const soDef of soRaw) {
        const expanded = expandStepDefs(
          soDef.steps.map((s) => ({ ref: s })),
          scenarioDefs,
          byId,
        );
        const soSteps = resolveStepDefs(expanded, scenarioDefs, byId);
        if (soSteps.length > 0) secondOrders.push({ steps: soSteps });
      }
    }
    steps.push({
      operation: op,
      link,
      secondOrders: secondOrders.length > 0 ? secondOrders : undefined,
      scannable: defs[i].scannable ?? true,
    });
  }
  return steps;
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
    const steps = resolveStepDefs(expanded, scenarioDefs, byId);
    if (steps.length === 0) continue;
    if (!steps[steps.length - 1].scannable) continue;

    sources.push({ steps });
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
    return {
      id: scenarioId(),
      name,
      type: OpenApiScenarioType,
      source,
    };
  });
}
