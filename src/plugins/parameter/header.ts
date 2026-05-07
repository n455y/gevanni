import {
  TamperMethod,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.js";
import type { Payload } from "../../types/branded.js";
import { InspectionParameter, TamperInstruction } from "../../types/models.js";
import type { HttpRequest } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";

class HeaderParameter extends InspectionParameter<{ name: string }, string> {
  createInstruction(
    payload: Payload,
    method: TamperMethod,
  ): HeaderTamperInstruction {
    return new HeaderTamperInstruction(this, payload, method);
  }
}

class HeaderTamperInstruction extends TamperInstruction<HeaderParameter> {}

class HeaderParserPlugin implements Plugin {
  readonly name = "header-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ParseRequestCommand,
      async (cmd: ParseRequestCommand) => {
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
      async (
        cmd: ApplyTamperCommand,
        request: HttpRequest,
      ): Promise<HttpRequest> => {
        const headerInstructions = cmd.instructions.filter(
          (instr): instr is HeaderTamperInstruction =>
            instr instanceof HeaderTamperInstruction,
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

function parseHeaderParameters(
  request: HttpRequest,
): InspectionParameter<unknown, unknown>[] {
  const params: InspectionParameter<unknown, unknown>[] = [];

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
  method: TamperMethod,
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
  HeaderTamperInstruction,
};
