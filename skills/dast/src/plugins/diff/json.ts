import type { PluginContext } from "../../core/plugin.ts";
import type { Exchange } from "../../types/models.ts";
import type { DiffPlugin, DiffResult } from "./base.ts";

function isJsonContentType(exchange: Exchange): boolean {
  const ct = exchange.response.headers["content-type"] ?? "";
  return ct.includes("application/json");
}

function jsonStructure(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object") return typeof obj;
  if (Array.isArray(obj)) return obj.map(jsonStructure);
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    result[key] = jsonStructure((obj as Record<string, unknown>)[key]);
  }
  return result;
}

export default class JsonDiffPlugin implements DiffPlugin {
  readonly name = "diff:json";

  async init(_context: PluginContext): Promise<void> {}

  compare(
    left: Exchange,
    right: Exchange,
    _options?: Record<string, unknown>,
  ): DiffResult {
    if (!isJsonContentType(left) || !isJsonContentType(right)) {
      return { hasDifferent: false };
    }

    let structA: unknown;
    let structB: unknown;
    try {
      structA = JSON.parse(left.response.body?.toString() ?? "");
      structB = JSON.parse(right.response.body?.toString() ?? "");
    } catch {
      return { hasDifferent: false };
    }

    const different =
      JSON.stringify(jsonStructure(structA)) !==
        JSON.stringify(jsonStructure(structB)) ||
      left.response.statusCode !== right.response.statusCode;

    return { hasDifferent: different };
  }
}
