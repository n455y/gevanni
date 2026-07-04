import { BuiltinMutationType } from "../../../types/models.ts";
import type { HttpRequest } from "../../../types/models.ts";
import type { ParserPlugin, PluginContext } from "../../../core/plugin.ts";
import { ParseRequestCommand } from "../../../commands/parse-request.ts";
import { PathParameter } from "./model.ts";

/** Lightweight subset of OpenApiOperation used to extract path parameters. */
interface StepOperation {
  path?: string;
  parameters?: Array<{ name: string; in: string }>;
}

interface ScenarioSource {
  steps?: Array<{ operation: StepOperation }>;
}

export default class PathParserPlugin implements ParserPlugin {
  readonly name = "parser:path";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      const source = (cmd.scenario as { source?: unknown } | undefined)
        ?.source as ScenarioSource | undefined;
      return parsePathParameters(cmd.request, source);
    });
  }
}

function parsePathParameters(
  request: HttpRequest,
  source?: ScenarioSource,
): PathParameter[] {
  const params: PathParameter[] = [];
  if (!source?.steps?.[0]?.operation?.path) return params;

  const operation = source.steps[0].operation;
  const pathTemplate = operation.path;
  if (!pathTemplate) return params;

  const pathParams = (operation.parameters ?? []).filter(
    (p) => p.in === "path",
  );
  if (pathParams.length === 0) return params;

  const currentPathname = new URL(request.url).pathname;

  for (const paramDef of pathParams) {
    const paramName = paramDef.name;

    // Escape path-template characters then replace {param} with a capture group
    const escapedTemplate = pathTemplate.replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&",
    );
    const regexStr = escapedTemplate.replace(
      `\\{${paramName}\\}`,
      "([^/]+)",
    );
    const regex = new RegExp(regexStr);
    const match = currentPathname.match(regex);

    if (match?.[1]) {
      const currentValue = decodeURIComponent(match[1]);
      params.push(
        new PathParameter({ name: paramName }, currentValue, [
          BuiltinMutationType.ReplaceValue,
          BuiltinMutationType.AppendValue,
          BuiltinMutationType.PrependValue,
        ]),
      );
    }
  }

  return params;
}
