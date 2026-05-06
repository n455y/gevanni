import {
  TamperMethod,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.js";
import type { HttpRequest } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import { HeaderParameterType } from "../parser/header-parser.js";

function applyTamper(
  current: string,
  payload: string,
  method: typeof TamperMethod,
): string {
  switch (method) {
    case ReplaceValue:
      return payload;
    case AppendValue:
      return current + payload;
    case PrependValue:
      return payload + current;
    default:
      return current;
  }
}

class HeaderTamperPlugin implements Plugin {
  readonly name = "header-tamper";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ApplyTamperCommand,
      async (
        cmd: ApplyTamperCommand,
        request: HttpRequest,
      ): Promise<HttpRequest> => {
        const headerInstructions = cmd.instructions.filter(
          (instr) => instr.parameter.type === HeaderParameterType,
        );

        if (headerInstructions.length === 0) {
          return request;
        }

        const headers = { ...request.headers };

        for (const instr of headerInstructions) {
          const paramName = (instr.parameter.location as { name: string })
            .name;
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

export { HeaderTamperPlugin };
