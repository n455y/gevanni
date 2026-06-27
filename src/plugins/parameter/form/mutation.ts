import type { MutationType } from "../../../types/branded.ts";
import { BuiltinMutationType } from "../../../types/models.ts";
import type { MutationPlugin, PluginContext } from "../../../core/plugin.ts";
import { ApplyMutationCommand } from "../../../commands/mutation.ts";
import { FormMutation } from "./model.ts";

export default class FormMutationPlugin implements MutationPlugin {
  readonly name = "mutation:form";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ApplyMutationCommand, async (cmd, request) => {
      const contentType = request.headers["content-type"] ?? "";
      if (!contentType.includes("application/x-www-form-urlencoded")) {
        return request;
      }

      if (!request.body) {
        return request;
      }

      const formBody = new URLSearchParams(request.body.toString("utf-8"));

      const formMutations = cmd.mutations
        .filter((instr): instr is FormMutation => instr instanceof FormMutation)
        .filter((instr) => formBody.has(instr.parameter.location.name));

      if (formMutations.length === 0) {
        return request;
      }

      for (const instr of formMutations) {
        const parameterName = instr.parameter.location.name;
        const current = formBody.get(parameterName) ?? "";
        const payload = String(instr.payload);
        const modified = applyMutation(current, payload, instr.mutationType);
        formBody.set(parameterName, modified);
      }

      return {
        method: request.method,
        url: request.url,
        headers: request.headers,
        body: Buffer.from(formBody.toString(), "utf-8"),
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
