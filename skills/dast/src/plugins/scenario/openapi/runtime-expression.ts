import type { HttpResponse } from "../../../types/models.ts";

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

export function resolveJsonPointer(data: unknown, pointer: string): unknown {
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
