import type { Plugin, PluginContext } from "../../core/plugin.ts";
import { DiffCommand, type DiffResult } from "../../commands/diff.ts";

export class ExactDiffPlugin implements Plugin {
  readonly name = "diff:exact";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(DiffCommand, async (cmd, acc): Promise<DiffResult> => {
      if (acc.handled) return acc;

      const [first, second] = cmd.pairs;
      if (!first || !second) return acc;

      const firstBody = first.exchange.response.body?.toString() ?? "";
      const secondBody = second.exchange.response.body?.toString() ?? "";
      const firstStatus = first.exchange.response.statusCode;
      const secondStatus = second.exchange.response.statusCode;

      const different =
        firstBody !== secondBody || firstStatus !== secondStatus;

      return {
        handled: true,
        different,
        evidenceExchanges: different
          ? [first.exchange, second.exchange]
          : [],
      };
    });
  }
}
