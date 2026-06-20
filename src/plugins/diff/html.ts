import type { PluginContext } from "../../core/plugin.ts";
import type { Exchange } from "../../types/models.ts";
import type { DiffPlugin, DiffResult } from "./base.ts";

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

export class HtmlDiffPlugin implements DiffPlugin {
  readonly name = "diff:html";

  async init(_context: PluginContext): Promise<void> {}

  compare(left: Exchange, right: Exchange): DiffResult {
    if (!isHtmlContentType(left) || !isHtmlContentType(right)) {
      return { hasDifferent: false };
    }

    const leftBody = normalizeHtml(left.response.body?.toString() ?? "");
    const rightBody = normalizeHtml(right.response.body?.toString() ?? "");
    const different =
      leftBody !== rightBody ||
      left.response.statusCode !== right.response.statusCode;

    return { hasDifferent: different };
  }
}
