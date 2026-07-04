import type { PluginContext } from "../../core/plugin.ts";
import type { Exchange } from "../../types/models.ts";
import type { DiffPlugin, DiffResult } from "./base.ts";

export default class ExactDiffPlugin implements DiffPlugin {
  readonly name = "diff:exact";

  async init(_context: PluginContext): Promise<void> {}

  compare(
    left: Exchange,
    right: Exchange,
    _options?: Record<string, unknown>,
  ): DiffResult {
    const leftBody = left.response.body?.toString() ?? "";
    const rightBody = right.response.body?.toString() ?? "";
    const different =
      leftBody !== rightBody ||
      left.response.statusCode !== right.response.statusCode;

    return { hasDifferent: different };
  }
}
