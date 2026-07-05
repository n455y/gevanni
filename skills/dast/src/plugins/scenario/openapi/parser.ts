import type {
  OpenApiOperation,
  OpenApiParameter,
  OpenApiRequestBody,
  OpenApiLink,
  OpenApiSecurityScheme,
} from "./types.ts";
import { isObject, expandSchemaVariants } from "./schema.ts";

// --- $ref resolver ---

export class RefResolver {
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

// --- OpenAPI doc type guards ---

interface OpenApiDoc {
  openapi?: string;
  servers?: { url: string }[];
  paths?: Record<string, Record<string, unknown>>;
  components?: Record<string, unknown>;
}

export function isOpenApi3(data: unknown): data is OpenApiDoc {
  if (!isObject(data)) return false;
  return typeof data.openapi === "string" && data.openapi.startsWith("3.");
}

// --- Extraction helpers ---

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

export function extractSecurity(raw: unknown): string[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const names: string[] = [];
  for (const item of raw) {
    if (isObject(item)) {
      for (const key of Object.keys(item)) names.push(key);
    }
  }
  return names.length > 0 ? names : undefined;
}

export function extractSecuritySchemes(
  doc: OpenApiDoc,
): Record<string, OpenApiSecurityScheme> | undefined {
  const components = (doc as { components?: unknown }).components;
  const raw = isObject(components)
    ? (components as Record<string, unknown>).securitySchemes
    : undefined;
  if (!isObject(raw)) return undefined;
  const result: Record<string, OpenApiSecurityScheme> = {};
  for (const [name, def] of Object.entries(raw)) {
    if (!isObject(def)) continue;
    const tokenExpr = def["x-gevanni-token"];
    result[name] = {
      type: typeof def.type === "string" ? def.type : "",
      scheme: typeof def.scheme === "string" ? def.scheme : undefined,
      in: typeof def.in === "string" ? def.in : undefined,
      name: typeof def.name === "string" ? def.name : undefined,
      tokenExpr: typeof tokenExpr === "string" ? tokenExpr : undefined,
    };
  }
  return Object.keys(result).length > 0 ? result : undefined;
}

export function extractParameters(rawList: unknown, resolver: RefResolver): OpenApiParameter[] {
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

export function extractRequestBodyVariants(
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

export function extractLinks(responses: unknown): OpenApiLink[] {
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

export function extractOperations(doc: OpenApiDoc): OpenApiOperation[] {
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
      const security = extractSecurity(operation.security);

      const base = {
        baseUrl,
        method: method.toUpperCase(),
        path,
        operationId,
        summary: operation.summary as string | undefined,
        parameters,
        links: links.length > 0 ? links : undefined,
        security,
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
