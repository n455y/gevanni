import { TamperMethod, ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";
import type { Payload } from "../../types/branded.js";
import type {
  HttpRequest,
  JsonValue,
  JsonObject,
} from "../../types/models.js";
import { InspectionParameter, TamperInstruction } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";

class GraphQLQueryParameter extends InspectionParameter<{ field: string }, string> {
  createInstruction(payload: Payload, method: typeof TamperMethod): GraphQLQueryTamperInstruction {
    return new GraphQLQueryTamperInstruction(this, payload, method);
  }
}
class GraphQLVariableParameter extends InspectionParameter<{ path: string[] }, JsonValue> {
  createInstruction(payload: Payload, method: typeof TamperMethod): GraphQLVariableTamperInstruction {
    return new GraphQLVariableTamperInstruction(this, payload, method);
  }
}

class GraphQLQueryTamperInstruction extends TamperInstruction<GraphQLQueryParameter> {}
class GraphQLVariableTamperInstruction extends TamperInstruction<GraphQLVariableParameter> {}

type GraphQLTamperInstruction = GraphQLQueryTamperInstruction | GraphQLVariableTamperInstruction;

function isGraphQLInstruction(instr: TamperInstruction): instr is GraphQLTamperInstruction {
  return instr instanceof GraphQLQueryTamperInstruction
    || instr instanceof GraphQLVariableTamperInstruction;
}

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

class GraphQLTamperPlugin implements Plugin {
  readonly name = "graphql-tamper";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ApplyTamperCommand,
      async (
        cmd: ApplyTamperCommand,
        request: HttpRequest,
      ): Promise<HttpRequest> => {
        const graphqlInstructions = cmd.instructions.filter(isGraphQLInstruction);

        if (graphqlInstructions.length === 0) {
          return request;
        }

        if (!request.body) {
          return request;
        }

        let jsonBody: JsonValue;
        try {
          jsonBody = JSON.parse(request.body.toString("utf-8")) as JsonValue;
        } catch {
          return request;
        }

        for (const instr of graphqlInstructions) {
          if (instr instanceof GraphQLQueryTamperInstruction) {
            const field = instr.parameter.location.field;
            if (typeof jsonBody === "object" && jsonBody !== null && !Array.isArray(jsonBody) && field in jsonBody) {
              (jsonBody as Record<string, JsonValue>)[field] = applyTamperValue(
                (jsonBody as Record<string, JsonValue>)[field],
                instr.payload as string,
                instr.method,
              );
            }
          } else if (instr instanceof GraphQLVariableTamperInstruction) {
            const path = instr.parameter.location.path;
            jsonBody = applyAtPath(jsonBody, path, instr.payload as string, instr.method);
          }
        }

        return {
          method: request.method,
          url: request.url,
          headers: request.headers,
          body: Buffer.from(JSON.stringify(jsonBody), "utf-8"),
        };
      },
    );
  }
}

function parseGraphQLParameters(
  request: HttpRequest,
): InspectionParameter<unknown, unknown>[] {
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

  const params: InspectionParameter<unknown, unknown>[] = [];

  params.push(new GraphQLQueryParameter(
    { field: "query" },
    parsed.query,
    [...ALLOWED_TAMPERS],
  ));

  if (
    "operationName" in parsed &&
    typeof parsed.operationName === "string"
  ) {
    params.push(new GraphQLQueryParameter(
      { field: "operationName" },
      parsed.operationName,
      [...ALLOWED_TAMPERS],
    ));
  }

  if ("variables" in parsed && typeof parsed.variables === "object" && parsed.variables !== null && !Array.isArray(parsed.variables)) {
    extractVariableParams(parsed.variables as JsonObject, ["variables"], params);
  }

  return params;
}

function extractVariableParams(
  obj: JsonObject,
  path: string[],
  params: InspectionParameter<unknown, unknown>[],
): void {
  for (const [key, value] of Object.entries(obj)) {
    const currentPath = [...path, key];
    if (
      value === null ||
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    ) {
      params.push(new GraphQLVariableParameter(
        { path: currentPath },
        value,
        [...ALLOWED_TAMPERS],
      ));
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

function applyAtPath(
  root: JsonValue,
  path: string[],
  payload: string,
  method: typeof TamperMethod,
): JsonValue {
  if (path.length === 0) {
    return applyTamperValue(root, payload, method);
  }

  if (typeof root !== "object" || root === null) {
    return root;
  }

  if (Array.isArray(root)) {
    const index = Number(path[0]);
    if (Number.isNaN(index) || index < 0 || index >= root.length) {
      return root;
    }
    const copy = [...root];
    copy[index] = applyAtPath(copy[index], path.slice(1), payload, method);
    return copy;
  }

  const key = path[0];
  if (!(key in root)) {
    return root;
  }
  const copy = { ...root };
  copy[key] = applyAtPath(copy[key] as JsonValue, path.slice(1), payload, method);
  return copy;
}

function applyTamperValue(
  current: JsonValue,
  payload: string,
  method: typeof TamperMethod,
): JsonValue {
  switch (method) {
    case ReplaceValue:
      return payload;
    case AppendValue:
      return String(current) + payload;
    case PrependValue:
      return payload + String(current);
    default:
      return current;
  }
}

export { GraphQLParserPlugin, GraphQLTamperPlugin, GraphQLQueryParameter, GraphQLVariableParameter, GraphQLQueryTamperInstruction, GraphQLVariableTamperInstruction };
