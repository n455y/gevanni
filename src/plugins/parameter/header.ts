import {
  MutationType,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.js";
import type { Payload } from "../../types/branded.js";
import { AuditTarget, AuditMutation } from "../../types/models.js";
import { serializable } from "../../types/serializable.js";
import type { HttpRequest } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { ApplyMutationCommand } from "../../commands/mutation.js";

class HeaderParameter extends AuditTarget<{ name: string }, string> {
  static kind = "header";
  createMutation(
    payload: Payload,
    method: MutationType,
  ): HeaderMutation {
    return new HeaderMutation(this, payload, method);
  }
}
serializable(HeaderParameter);

class HeaderMutation extends AuditMutation<HeaderParameter> {}

class HeaderParserPlugin implements Plugin {
  readonly name = "header-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ParseRequestCommand,
      async (cmd) => {
        return parseHeaderParameters(cmd.request);
      },
    );
  }
}

class HeaderMutationPlugin implements Plugin {
  readonly name = "header-mutation";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ApplyMutationCommand,
      async (cmd, request) => {
        const headerMutations = cmd.mutations.filter(
          (instr): instr is HeaderMutation =>
            instr instanceof HeaderMutation,
        );

        if (headerMutations.length === 0) {
          return request;
        }

        const headers = { ...request.headers };

        for (const instr of headerMutations) {
          const targetName = instr.target.location.name;
          const current = headers[targetName] ?? "";
          const payload = instr.payload as string;
          headers[targetName] = applyMutation(current, payload, instr.method);
        }

        return {
          method: request.method,
          url: request.url,
          headers,
          body: request.body,
        };
      },
    );
  }
}

function parseHeaderParameters(request: HttpRequest): AuditTarget[] {
  const params: AuditTarget[] = [];

  for (const [name, value] of Object.entries(request.headers)) {
    params.push(
      new HeaderParameter({ name }, value, [
        ReplaceValue,
        AppendValue,
        PrependValue,
      ]),
    );
  }

  return params;
}

function applyMutation(
  current: string,
  payload: string,
  method: MutationType,
): string {
  switch (method) {
    case ReplaceValue:
      return payload;
    case PrependValue:
      return payload + current;
    case AppendValue:
      return current + payload;
    default:
      return current;
  }
}

export {
  HeaderParserPlugin,
  HeaderMutationPlugin,
  HeaderParameter,
  HeaderMutation,
};
