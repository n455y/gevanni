import {
  ParameterType,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.js";
import type { HttpRequest, InspectionParameter } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";

class QueryParameterType extends ParameterType {}

type QueryParameter = InspectionParameter<
  typeof QueryParameterType,
  { name: string },
  string
>;

class QueryParserPlugin implements Plugin {
  readonly name = "query-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ParseRequestCommand,
      async (cmd: ParseRequestCommand) => {
        return parseQueryParameters(cmd.request);
      },
    );
  }
}

function parseQueryParameters(request: HttpRequest): InspectionParameter[] {
  const url = new URL(request.url);
  const params: InspectionParameter[] = [];

  for (const [name, value] of url.searchParams) {
    const param: QueryParameter = {
      type: QueryParameterType,
      location: { name },
      originalValue: value,
      allowedTampers: [ReplaceValue, AppendValue, PrependValue],
    };
    params.push(param);
  }

  return params;
}

export type { QueryParameter };
export { QueryParserPlugin, QueryParameterType };
