import { BuiltinMutationType } from "../../../types/models.ts";
import type { AuditParameter, HttpRequest } from "../../../types/models.ts";
import type { ParserPlugin, PluginContext } from "../../../core/plugin.ts";
import { ParseRequestCommand } from "../../../commands/parse-request.ts";
import { HeaderParameter } from "./model.ts";

export default class HeaderParserPlugin implements ParserPlugin {
  readonly name = "parser:header";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseHeaderParameters(cmd.request);
    });
  }
}

const EXCLUDED_HEADERS = [
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "cookie",
];

function parseHeaderParameters(request: HttpRequest): AuditParameter[] {
  const params: AuditParameter[] = [];

  for (const [name, value] of Object.entries(request.headers)) {
    if (EXCLUDED_HEADERS.includes(name.toLowerCase())) continue;
    params.push(
      new HeaderParameter({ name }, value, [
        BuiltinMutationType.ReplaceValue,
        BuiltinMutationType.AppendValue,
        BuiltinMutationType.PrependValue,
      ]),
    );
  }

  return params;
}
