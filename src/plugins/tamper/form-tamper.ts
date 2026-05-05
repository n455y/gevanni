import type { Brand, TamperMethod } from "../../types/branded.js";
import type { HttpRequest, TamperInstruction } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";

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

        const formInstructions = cmd.instructions.filter((instr) => {
          if (
            instr.parameter.type !==
            ("query" as Brand<"query", "ParameterType">)
          ) {
            return false;
          }
          const paramName = (instr.parameter.location as { name: string })
            .name;
          return formBody.has(paramName);
        });

        if (formInstructions.length === 0) {
          return request;
        }

        for (const instr of formInstructions) {
          const paramName = (instr.parameter.location as { name: string })
            .name;
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

function applyTamper(
  current: string,
  payload: string,
  method: TamperMethod,
): string {
  switch (method) {
    case "replaceValue" as TamperMethod:
      return payload;
    case "appendValue" as TamperMethod:
      return current + payload;
    case "prependValue" as TamperMethod:
      return payload + current;
    default:
      return current;
  }
}

export { FormTamperPlugin };
