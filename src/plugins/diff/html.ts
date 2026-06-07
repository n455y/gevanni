import type { Plugin, PluginContext } from "../../core/plugin.ts";
import { DiffCommand, type DiffResult } from "../../commands/diff.ts";
import type { Exchange } from "../../types/models.ts";

function isHtmlContentType(exchange: Exchange): boolean {
  const ct = exchange.response.headers["content-type"] ?? "";
  return ct.includes("text/html");
}

function normalizeHtml(html: string): string {
  let result = html;
  result = result.replace(/<script[\s>][\s\S]*?<\/script>/gi, "");
  result = result.replace(/<style[\s>][\s\S]*?<\/style>/gi, "");
  result = result.replace(/="[^"]*"/g, "");
  result = result.replace(/\s+/g, " ");
  result = result.replace(/ ?< ?/g, "<");
  result = result.replace(/ ?> ?/g, ">");
  return result.trim();
}

export class HtmlDiffPlugin implements Plugin {
  readonly name = "diff:html";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(DiffCommand, async (cmd, acc): Promise<DiffResult> => {
      if (acc.handled) return acc;

      const [first, second] = cmd.pairs;
      if (!first || !second) return acc;
      if (!isHtmlContentType(first.exchange) || !isHtmlContentType(second.exchange)) return acc;

      const firstBody = normalizeHtml(first.exchange.response.body?.toString() ?? "");
      const secondBody = normalizeHtml(second.exchange.response.body?.toString() ?? "");
      const firstStatus = first.exchange.response.statusCode;
      const secondStatus = second.exchange.response.statusCode;

      const different = firstBody !== secondBody || firstStatus !== secondStatus;

      return {
        handled: true,
        different,
        evidenceExchanges: different ? [first.exchange, second.exchange] : [],
      };
    });
  }
}
