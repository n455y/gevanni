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

class FormParameter extends InspectionParameter<{ name: string }, string> {
  createInstruction(
    payload: Payload,
    method: TamperMethod,
  ): FormTamperInstruction {
    return new FormTamperInstruction(this, payload, method);
  }
}

class FormTamperInstruction extends TamperInstruction<FormParameter> {}

class FormParserPlugin implements Plugin {
  readonly name = "form-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ParseRequestCommand,
      async (cmd: ParseRequestCommand) => {
        return parseFormParameters(cmd.request);
      },
    );
  }
}

class FormTamperPlugin implements Plugin {
  readonly name = "form-tamper";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ApplyTamperCommand,
      async (
        cmd: ApplyTamperCommand,
        request: HttpRequest,
      ): Promise<HttpRequest> => {
        const contentType = request.headers["content-type"] ?? "";
        if (!contentType.includes("application/x-www-form-urlencoded")) {
          return request;
        }

        if (!request.body) {
          return request;
        }

        const formBody = new URLSearchParams(request.body.toString("utf-8"));

        const formInstructions = cmd.instructions
          .filter(
            (instr): instr is FormTamperInstruction =>
              instr instanceof FormTamperInstruction,
          )
          .filter((instr) => formBody.has(instr.parameter.location.name));

        if (formInstructions.length === 0) {
          return request;
        }

        for (const instr of formInstructions) {
          const paramName = instr.parameter.location.name;
          const current = formBody.get(paramName) ?? "";
          const payload = instr.payload as string;
          const modified = applyTamper(current, payload, instr.method);
          formBody.set(paramName, modified);
        }

        return {
          method: request.method,
          url: request.url,
          headers: request.headers,
          body: Buffer.from(formBody.toString(), "utf-8"),
        };
      },
    );
  }
}

function parseFormParameters(
  request: HttpRequest,
): InspectionParameter<unknown, unknown>[] {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return [];
  }

  if (!request.body) {
    return [];
  }

  const searchParams = new URLSearchParams(request.body.toString("utf-8"));
  const params: InspectionParameter<unknown, unknown>[] = [];

  for (const [name, value] of searchParams) {
    params.push(
      new FormParameter({ name }, value, [
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
    case AppendValue:
      return current + payload;
    case PrependValue:
      return payload + current;
    default:
      return current;
  }
}

export {
  FormParserPlugin,
  FormTamperPlugin,
  FormParameter,
  FormTamperInstruction,
};
