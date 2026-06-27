import type { MutationType } from "../../../types/branded.ts";
import { BuiltinMutationType } from "../../../types/models.ts";
import type { MutationPlugin, PluginContext } from "../../../core/plugin.ts";
import { ApplyMutationCommand } from "../../../commands/mutation.ts";
import { CookieMutation, parseCookieHeader } from "./model.ts";

export default class CookieMutationPlugin implements MutationPlugin {
  readonly name = "mutation:cookie";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ApplyMutationCommand, async (cmd, request) => {
      const cookieMutations = cmd.mutations.filter(
        (instr): instr is CookieMutation => instr instanceof CookieMutation,
      );

      if (cookieMutations.length === 0) {
        return request;
      }

      const cookies = parseCookieHeader(request.headers["cookie"] ?? "");

      for (const instr of cookieMutations) {
        const cookieName = instr.parameter.location.name;
        const current = cookies.get(cookieName) ?? "";
        const payload = String(instr.payload);
        cookies.set(cookieName, applyMutation(current, payload, instr.mutationType));
      }

      const headers = { ...request.headers };
      const cookieValue = [...cookies.entries()]
        .map(([k, v]) => `${k}=${v}`)
        .join("; ");

      if (cookieValue) {
        headers["cookie"] = cookieValue;
      } else {
        delete headers["cookie"];
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
