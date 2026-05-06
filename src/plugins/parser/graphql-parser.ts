import {
  ParameterType,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.js";
import type {
  HttpRequest,
  InspectionParameter,
  JsonValue,
  JsonObject,
} from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";

class GraphQLQueryParameterType extends ParameterType {}
class GraphQLVariableParameterType extends ParameterType {}

type GraphQLQueryParameter = InspectionParameter<
  typeof GraphQLQueryParameterType,
  { field: string },
  string
>;

type GraphQLVariableParameter = InspectionParameter<
  typeof GraphQLVariableParameterType,
  { path: string[] },
  JsonValue
>;

const ALLOWED_TAMPERS = [ReplaceValue, AppendValue, PrependValue];

class GraphQLParserPlugin implements Plugin {
  readonly name = "graphql-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ParseRequestCommand,
      async (cmd: ParseRequestCommand) => {
        return parseGraphQLParameters(cmd.request);
      },
    );
  }
}

function parseGraphQLParameters(
  request: HttpRequest,
): InspectionParameter[] {
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

  const params: InspectionParameter[] = [];

  params.push({
    type: GraphQLQueryParameterType,
    location: { field: "query" },
    originalValue: parsed.query,
    allowedTampers: [...ALLOWED_TAMPERS],
  } satisfies GraphQLQueryParameter);

  if (
    "operationName" in parsed &&
    typeof parsed.operationName === "string"
  ) {
    params.push({
      type: GraphQLQueryParameterType,
      location: { field: "operationName" },
      originalValue: parsed.operationName,
      allowedTampers: [...ALLOWED_TAMPERS],
    } satisfies GraphQLQueryParameter);
  }

  if ("variables" in parsed && typeof parsed.variables === "object" && parsed.variables !== null && !Array.isArray(parsed.variables)) {
    extractVariableParams(parsed.variables as JsonObject, ["variables"], params);
  }

  return params;
}

function extractVariableParams(
  obj: JsonObject,
  path: string[],
  params: InspectionParameter[],
): void {
  for (const [key, value] of Object.entries(obj)) {
    const currentPath = [...path, key];
    if (
      value === null ||
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    ) {
      params.push({
        type: GraphQLVariableParameterType,
        location: { path: currentPath },
        originalValue: value,
        allowedTampers: [...ALLOWED_TAMPERS],
      });
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

export {
  GraphQLParserPlugin,
  GraphQLQueryParameterType,
  GraphQLVariableParameterType,
};
export type { GraphQLQueryParameter, GraphQLVariableParameter };
