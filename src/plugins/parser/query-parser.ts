import type { Brand, TamperMethod } from "../../types/branded.js";
import type {
  HttpRequest,
  InspectionParameter,
  QueryParameter,
} from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";

function createQueryParserPlugin(): Plugin {
  return {
    name: "query-parser",

    async init(context: PluginContext): Promise<void> {
      context.commandBus.register(
        ParseRequestCommand,
        async (cmd: ParseRequestCommand) => {
          return parseQueryParameters(cmd.request);
        },
      );
    },
  };
}

function parseQueryParameters(
  request: HttpRequest,
): InspectionParameter[] {
  const url = new URL(request.url);
  const params: InspectionParameter[] = [];

  for (const [name, value] of url.searchParams) {
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

export { createQueryParserPlugin };
