import { BuiltinMutationType } from "../../types/branded.ts";
import type {
  AnyMutationType,
  MutationType,
  Payload,
} from "../../types/branded.ts";
import { AuditParameter, AuditMutation } from "../../types/models.ts";
import { serializable } from "../../types/serializable.ts";
import type { HttpRequest } from "../../types/models.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { ApplyMutationCommand } from "../../commands/mutation.ts";

export class HeaderParameter extends AuditParameter<{ name: string }, string> {
  static kind = "header";
  createMutation<P extends Payload>(
    payload: P,
    method: MutationType<P>,
  ): HeaderMutation {
    return new HeaderMutation(this, payload, method);
  }
}
serializable(HeaderParameter);

export class HeaderMutation extends AuditMutation<HeaderParameter> {}

export class HeaderParserPlugin implements Plugin {
  readonly name = "header-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseHeaderParameters(cmd.request);
    });
  }
}

export class HeaderMutationPlugin implements Plugin {
  readonly name = "header-mutation";

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
        headers[parameterName] = applyMutation(current, payload, instr.method);
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

function parseHeaderParameters(request: HttpRequest): AuditParameter[] {
  const params: AuditParameter[] = [];

  for (const [name, value] of Object.entries(request.headers)) {
    params.push(
      new HeaderParameter({ name }, value, [
        BuiltinMutationType.ReplaceValue,
        BuiltinMutationType.AppendValue,
        BuiltinMutationType.PrependValue,
      ]),
    );
  }

  return params;
}

function applyMutation(
  current: string,
  payload: string,
  method: AnyMutationType,
): string {
  switch (method) {
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
