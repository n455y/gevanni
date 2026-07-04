import { BuiltinMutationType } from "../../../types/models.ts";
import type { AuditParameter, HttpRequest } from "../../../types/models.ts";
import type { ParserPlugin, PluginContext } from "../../../core/plugin.ts";
import { ParseRequestCommand } from "../../../commands/parse-request.ts";
import { CookieParameter, parseCookieHeader } from "./model.ts";

export default class CookieParserPlugin implements ParserPlugin {
  readonly name = "parser:cookie";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseCookieParameters(cmd.request);
    });
  }
}

function parseCookieParameters(request: HttpRequest): AuditParameter[] {
  const cookieHeader = request.headers["cookie"];
  if (!cookieHeader) return [];

  const params: AuditParameter[] = [];

  for (const [name, value] of parseCookieHeader(cookieHeader)) {
    params.push(
      new CookieParameter({ name }, value, [
        BuiltinMutationType.ReplaceValue,
        BuiltinMutationType.AppendValue,
        BuiltinMutationType.PrependValue,
      ]),
    );
  }

  return params;
}
