import type { ReplayId } from "../../../types/branded.ts";
import type {
  OpenApiOperation,
  OpenApiRequestBody,
  OpenApiSecurityScheme,
} from "./types.ts";
import { defaultValueForSchema } from "./schema.ts";

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

export function applySecurity(
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
