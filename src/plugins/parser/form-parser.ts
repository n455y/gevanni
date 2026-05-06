import { ParameterType, ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";
import type {
  HttpRequest,
  InspectionParameter,
} from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { QueryParameterType } from "./query-parser.js";
import type { QueryParameter } from "./query-parser.js";

class FormParameterType extends ParameterType {}

type FormParameter = InspectionParameter<typeof FormParameterType, { name: string }, string>;

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
      type: QueryParameterType,
      location: { name },
      originalValue: value,
      allowedTampers: [
        ReplaceValue,
        AppendValue,
        PrependValue,
      ],
    };
    params.push(param);
  }

  return params;
}

export { FormParserPlugin, FormParameterType };
export type { FormParameter };
