import { BuiltinMutationType } from "../../../types/models.ts";
import type { AuditParameter, HttpRequest } from "../../../types/models.ts";
import type { ParserPlugin, PluginContext } from "../../../core/plugin.ts";
import { ParseRequestCommand } from "../../../commands/parse-request.ts";
import { QueryParameter } from "./model.ts";

export default class QueryParserPlugin implements ParserPlugin {
  readonly name = "parser:query";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseQueryParameters(cmd.request);
    });
  }
}

function parseQueryParameters(request: HttpRequest): AuditParameter[] {
  const url = new URL(request.url);
  const params: AuditParameter[] = [];

  for (const [name, value] of url.searchParams) {
    params.push(
      new QueryParameter({ name }, value, [
        BuiltinMutationType.ReplaceValue,
        BuiltinMutationType.AppendValue,
        BuiltinMutationType.PrependValue,
      ]),
    );
  }

  return params;
}
