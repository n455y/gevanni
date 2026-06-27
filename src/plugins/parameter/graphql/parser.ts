import { BuiltinMutationType } from "../../../types/models.ts";
import type {
  AuditParameter,
  HttpRequest,
  JsonObject,
  JsonValue,
} from "../../../types/models.ts";
import type { ParserPlugin, PluginContext } from "../../../core/plugin.ts";
import { ParseRequestCommand } from "../../../commands/parse-request.ts";
import { GraphQLQueryParameter, GraphQLVariableParameter } from "./model.ts";

const ALLOWED_MUTATIONS = [
  BuiltinMutationType.ReplaceValue,
  BuiltinMutationType.AppendValue,
  BuiltinMutationType.PrependValue,
];

export default class GraphQLParserPlugin implements ParserPlugin {
  readonly name = "parser:graphql";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseGraphQLParameters(cmd.request);
    });
  }
}

function parseGraphQLParameters(request: HttpRequest): AuditParameter[] {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.includes("application/json")) {
    return [];
  }

  if (!request.body) {
    return [];
  }

  let parsed: JsonValue;
  try {
    parsed = JSON.parse(request.body.toString("utf-8")) as JsonValue;
  } catch {
    return [];
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return [];
  }

  if (!("query" in parsed) || typeof parsed.query !== "string") {
    return [];
  }

  const params: AuditParameter[] = [];

  params.push(
    new GraphQLQueryParameter({ field: "query" }, parsed.query, [
      ...ALLOWED_MUTATIONS,
    ]),
  );

  if ("operationName" in parsed && typeof parsed.operationName === "string") {
    params.push(
      new GraphQLQueryParameter(
        { field: "operationName" },
        parsed.operationName,
        [...ALLOWED_MUTATIONS],
      ),
    );
  }

  if (
    "variables" in parsed &&
    typeof parsed.variables === "object" &&
    parsed.variables !== null &&
    !Array.isArray(parsed.variables)
  ) {
    extractVariableParams(
      parsed.variables as JsonObject,
      ["variables"],
      params,
    );
  }

  return params;
}

function extractVariableParams(
  obj: JsonObject,
  path: string[],
  params: AuditParameter[],
): void {
  for (const [key, value] of Object.entries(obj)) {
    const currentPath = [...path, key];
    if (
      value === null ||
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    ) {
      params.push(
        new GraphQLVariableParameter({ path: currentPath }, value, [
          ...ALLOWED_MUTATIONS,
        ]),
      );
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        extractVariableParams(
          { [String(i)]: value[i] } as JsonObject,
          currentPath,
          params,
        );
      }
    } else if (typeof value === "object") {
      extractVariableParams(value as JsonObject, currentPath, params);
    }
  }
}
