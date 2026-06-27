import type { MutationType } from "../../../types/branded.ts";
import { BuiltinMutationType } from "../../../types/models.ts";
import type { MutationPlugin, PluginContext } from "../../../core/plugin.ts";
import { ApplyMutationCommand } from "../../../commands/mutation.ts";
import { PathMutation } from "./model.ts";

export default class PathMutationPlugin implements MutationPlugin {
  readonly name = "mutation:path";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ApplyMutationCommand, async (cmd, request) => {
      const pathMutations = cmd.mutations.filter(
        (instr): instr is PathMutation => instr instanceof PathMutation,
      );
      if (pathMutations.length === 0) return request;

      const url = new URL(request.url);
      let pathname = url.pathname;

      for (const instr of pathMutations) {
        const current = instr.parameter.originalValue;
        const payload = String(instr.payload);
        const modified = applyMutation(current, payload, instr.mutationType);
        // Replace the current (URL-encoded) value with the new one
        pathname = pathname.replace(
          encodeURIComponent(current),
          encodeURIComponent(modified),
        );
      }

      url.pathname = pathname;

      return {
        method: request.method,
        url: url.toString(),
        headers: request.headers,
        body: request.body,
      };
    });
  }
}

function applyMutation(
  current: string,
  payload: string,
  mutationType: MutationType,
): string {
  switch (mutationType) {
    case BuiltinMutationType.ReplaceValue:
      return payload;
    case BuiltinMutationType.AppendValue:
      return current + payload;
    case BuiltinMutationType.PrependValue:
      return payload + current;
    default:
      return current;
  }
}
