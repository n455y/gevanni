import type { MutationType } from "../../../types/branded.ts";
import { BuiltinMutationType } from "../../../types/models.ts";
import type { MutationPlugin, PluginContext } from "../../../core/plugin.ts";
import { ApplyMutationCommand } from "../../../commands/mutation.ts";
import { HeaderMutation } from "./model.ts";

export default class HeaderMutationPlugin implements MutationPlugin {
  readonly name = "mutation:header";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ApplyMutationCommand, async (cmd, request) => {
      const headerMutations = cmd.mutations.filter(
        (instr): instr is HeaderMutation => instr instanceof HeaderMutation,
      );

      if (headerMutations.length === 0) {
        return request;
      }

      const headers = { ...request.headers };

      for (const instr of headerMutations) {
        const parameterName = instr.parameter.location.name;
        const current = headers[parameterName] ?? "";
        const payload = String(instr.payload);
        headers[parameterName] = applyMutation(
          current,
          payload,
          instr.mutationType,
        );
      }

      return {
        method: request.method,
        url: request.url,
        headers,
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
    case BuiltinMutationType.PrependValue:
      return payload + current;
    case BuiltinMutationType.AppendValue:
      return current + payload;
    default:
      return current;
  }
}
