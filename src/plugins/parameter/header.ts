import {
  MutationType,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.js";
import type { Payload } from "../../types/branded.js";
import { AuditTarget, AuditMutation } from "../../types/models.js";
import type { HttpRequest } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";

class HeaderParameter extends AuditTarget<{ name: string }, string> {
  createMutation(
    payload: Payload,
    method: MutationType,
  ): HeaderMutation {
    return new HeaderMutation(this, payload, method);
  }
}

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

class HeaderTamperPlugin implements Plugin {
  readonly name = "header-tamper";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ApplyTamperCommand,
      async (cmd, request) => {
        const headerInstructions = cmd.instructions.filter(
          (instr): instr is HeaderMutation =>
            instr instanceof HeaderMutation,
        );

        if (headerInstructions.length === 0) {
          return request;
        }

        const headers = { ...request.headers };

        for (const instr of headerInstructions) {
          const paramName = instr.parameter.location.name;
          const current = headers[paramName] ?? "";
          const payload = instr.payload as string;
          headers[paramName] = applyTamper(current, payload, instr.method);
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

function applyTamper(
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
  HeaderTamperPlugin,
  HeaderParameter,
  HeaderMutation,
};
