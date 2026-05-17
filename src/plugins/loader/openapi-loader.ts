import fs from "node:fs";
import crypto from "node:crypto";
import yaml from "js-yaml";
import type { Scenario } from "../../types/models.ts";
import { ScenarioId } from "../../types/branded.ts";
import { ScenarioType } from "../../types/branded.ts";
import type { ScenarioLoaderPlugin, PluginContext } from "../../core/plugin.ts";

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

export interface OpenApiOperation {
  baseUrl: string;
  method: string;
  path: string;
  operationId?: string;
  summary?: string;
  parameters: OpenApiParameter[];
  requestBody?: OpenApiRequestBody;
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

function defaultValueForSchema(
  schema?: { type?: string; [key: string]: unknown },
  example?: unknown,
): unknown {
  if (example !== undefined) return example;
  if (!schema) return "test";

  switch (schema.type) {
    case "integer":
    case "number":
      return 1;
    case "boolean":
      return true;
    case "array":
      return [];
    case "object":
      return {};
    default:
      return "test";
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

interface OpenApiDoc {
  openapi?: string;
  servers?: { url: string }[];
  paths?: Record<string, Record<string, unknown>>;
}

function isOpenApi3(data: unknown): data is OpenApiDoc {
  if (!isObject(data)) return false;
  return typeof data.openapi === "string" && data.openapi.startsWith("3.");
}

function extractOperations(doc: OpenApiDoc): OpenApiOperation[] {
  const baseUrl = doc.servers?.[0]?.url ?? "http://localhost";
  const operations: OpenApiOperation[] = [];

  for (const [path, pathItem] of Object.entries(doc.paths ?? {})) {
    if (!isObject(pathItem)) continue;

    for (const method of HTTP_METHODS) {
      const operation = pathItem[method];
      if (!isObject(operation)) continue;

      const parameters: OpenApiParameter[] = [];
      // Path-level parameters
      const pathLevelParams = pathItem.parameters;
      if (Array.isArray(pathLevelParams)) {
        for (const p of pathLevelParams) {
          if (isObject(p) && !("$ref" in p)) {
            parameters.push({
              name: p.name as string,
              in: p.in as OpenApiParameter["in"],
              required: p.required as boolean | undefined,
              schema: p.schema as OpenApiParameter["schema"],
              example: p.example,
            });
          }
        }
      }
      // Operation-level parameters
      const opParams = operation.parameters;
      if (Array.isArray(opParams)) {
        for (const p of opParams) {
          if (isObject(p) && !("$ref" in p)) {
            parameters.push({
              name: p.name as string,
              in: p.in as OpenApiParameter["in"],
              required: p.required as boolean | undefined,
              schema: p.schema as OpenApiParameter["schema"],
              example: p.example,
            });
          }
        }
      }

      let requestBody: OpenApiRequestBody | undefined;
      const opBody = operation.requestBody;
      if (isObject(opBody) && !("$ref" in opBody)) {
        const content = opBody.content as Record<string, unknown> | undefined;
        if (isObject(content)) {
          const ct = Object.keys(content)[0];
          const mediaType = content[ct] as Record<string, unknown>;
          requestBody = {
            contentType: ct,
            schema: mediaType?.schema as OpenApiRequestBody["schema"],
            example: mediaType?.example,
          };
        }
      }

      operations.push({
        baseUrl,
        method: method.toUpperCase(),
        path,
        operationId: operation.operationId as string | undefined,
        summary: operation.summary as string | undefined,
        parameters,
        requestBody,
      });
    }
  }

  return operations;
}

export { defaultValueForSchema, extractOperations, isOpenApi3 };

// --- Plugin ---

export const OpenApiScenarioType = ScenarioType("openapi");

export class OpenApiLoaderPlugin implements ScenarioLoaderPlugin {
  readonly name = "openapi-loader";

  async init(_context: PluginContext): Promise<void> {}

  async load(source: unknown): Promise<Scenario[]> {
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

    return operations.map((op) => ({
      id: scenarioId(),
      name: op.operationId ?? op.summary ?? `${op.method} ${op.path}`,
      type: OpenApiScenarioType,
      source: op,
    }));
  }
}
