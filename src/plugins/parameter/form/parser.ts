import { BuiltinMutationType } from "../../../types/models.ts";
import type { AuditParameter, HttpRequest } from "../../../types/models.ts";
import type { ParserPlugin, PluginContext } from "../../../core/plugin.ts";
import { ParseRequestCommand } from "../../../commands/parse-request.ts";
import { FormParameter } from "./model.ts";

export default class FormParserPlugin implements ParserPlugin {
  readonly name = "parser:form";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseFormParameters(cmd.request);
    });
  }
}

function parseFormParameters(request: HttpRequest): AuditParameter[] {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return [];
  }

  if (!request.body) {
    return [];
  }

  const searchParams = new URLSearchParams(request.body.toString("utf-8"));
  const params: AuditParameter[] = [];

  for (const [name, value] of searchParams) {
    params.push(
      new FormParameter({ name }, value, [
        BuiltinMutationType.ReplaceValue,
        BuiltinMutationType.AppendValue,
        BuiltinMutationType.PrependValue,
      ]),
    );
  }

  return params;
}
