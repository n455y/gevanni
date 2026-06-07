import type { Plugin, PluginContext } from "../../core/plugin.ts";
import { DiffCommand, type DiffResult } from "../../commands/diff.ts";
import type { Exchange } from "../../types/models.ts";

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

export class JsonDiffPlugin implements Plugin {
  readonly name = "diff:json";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      DiffCommand,
      async (cmd, acc): Promise<DiffResult> => {
        if (acc.handled) return acc;

        const [first, second] = cmd.pairs;
        if (!first || !second) return acc;
        if (
          !isJsonContentType(first.exchange) ||
          !isJsonContentType(second.exchange)
        )
          return acc;

        let structA: unknown;
        let structB: unknown;
        try {
          structA = jsonStructure(
            JSON.parse(first.exchange.response.body?.toString() ?? ""),
          );
          structB = jsonStructure(
            JSON.parse(second.exchange.response.body?.toString() ?? ""),
          );
        } catch {
          return acc;
        }

        const firstStatus = first.exchange.response.statusCode;
        const secondStatus = second.exchange.response.statusCode;
        const different =
          JSON.stringify(structA) !== JSON.stringify(structB) ||
          firstStatus !== secondStatus;

        return {
          handled: true,
          different,
          evidenceExchanges: different ? [first.exchange, second.exchange] : [],
        };
      },
    );
  }
}
