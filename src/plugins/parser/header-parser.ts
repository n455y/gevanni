import {
  ParameterType,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.js";

class HeaderParameterType extends ParameterType {}
import type { HttpRequest, InspectionParameter } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";

type HeaderParameter = InspectionParameter<
  typeof HeaderParameterType,
  { name: string },
  string
>;

export type { HeaderParameter };

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

function parseHeaderParameters(request: HttpRequest): InspectionParameter[] {
  const params: InspectionParameter[] = [];

  for (const [name, value] of Object.entries(request.headers)) {
    const param: HeaderParameter = {
      type: HeaderParameterType,
      location: { name },
      originalValue: value,
      allowedTampers: [ReplaceValue, AppendValue, PrependValue],
    };
    params.push(param);
  }

  return params;
}

export { HeaderParserPlugin, HeaderParameterType };
