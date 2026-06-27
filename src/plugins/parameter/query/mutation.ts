import type { MutationType } from "../../../types/branded.ts";
import { BuiltinMutationType } from "../../../types/models.ts";
import type { HttpRequest } from "../../../types/models.ts";
import type { MutationPlugin, PluginContext } from "../../../core/plugin.ts";
import { ApplyMutationCommand } from "../../../commands/mutation.ts";
import { QueryMutation } from "./model.ts";

export default class QueryMutationPlugin implements MutationPlugin {
  readonly name = "mutation:query";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ApplyMutationCommand, async (cmd, request) => {
      const queryMutations = cmd.mutations.filter(
        (instr): instr is QueryMutation => instr instanceof QueryMutation,
      );

      if (queryMutations.length === 0) {
        return request;
      }

      const url = new URL(request.url);
      const searchParams = new URLSearchParams(url.search);

      for (const instr of queryMutations) {
        const parameterName = instr.parameter.location.name;
        const current = searchParams.get(parameterName) ?? "";
        const payload = String(instr.payload);
        const modified = applyMutation(current, payload, instr.mutationType);
        searchParams.set(parameterName, modified);
      }

      url.search = searchParams.toString();

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
