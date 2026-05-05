import type { Brand, TamperMethod } from "../../types/branded.js";
import type {
  HttpRequest,
  InspectionParameter,
  QueryParameter,
} from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";

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

function parseFormParameters(request: HttpRequest): InspectionParameter[] {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return [];
  }

  if (!request.body) {
    return [];
  }

  const searchParams = new URLSearchParams(request.body.toString("utf-8"));
  const params: InspectionParameter[] = [];

  for (const [name, value] of searchParams) {
    const param: QueryParameter = {
      type: "query" as Brand<"query", "ParameterType">,
      location: { name },
      originalValue: value,
      allowedTampers: [
        "replaceValue" as TamperMethod,
        "appendValue" as TamperMethod,
        "prependValue" as TamperMethod,
      ],
    };
    params.push(param);
  }

  return params;
}

export { FormParserPlugin };
