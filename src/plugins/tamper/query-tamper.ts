import { TamperMethod, ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";
import type { HttpRequest, TamperInstruction } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import { QueryParameterType } from "../parser/query-parser.js";

class QueryTamperPlugin implements Plugin {
  readonly name = "query-tamper";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ApplyTamperCommand,
      async (
        cmd: ApplyTamperCommand,
        request: HttpRequest,
      ): Promise<HttpRequest> => {
        const queryInstructions = cmd.instructions.filter(
          (instr) =>
            instr.parameter.type === QueryParameterType,
        );

        if (queryInstructions.length === 0) {
          return request;
        }

        const url = new URL(request.url);
        const searchParams = new URLSearchParams(url.search);

        for (const instr of queryInstructions) {
          const paramName = (instr.parameter.location as { name: string })
            .name;
          const current = searchParams.get(paramName) ?? "";
          const payload = instr.payload as string;
          const modified = applyTamper(
            current,
            payload,
            instr.method,
          );
          searchParams.set(paramName, modified);
        }

        url.search = searchParams.toString();

        return {
          method: request.method,
          url: url.toString(),
          headers: request.headers,
          body: request.body,
        };
      },
    );
  }
}

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

export { QueryTamperPlugin };
