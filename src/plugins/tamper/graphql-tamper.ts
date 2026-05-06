import { TamperMethod, ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";
import type { HttpRequest, JsonValue } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import {
  GraphQLQueryParameterType,
  GraphQLVariableParameterType,
} from "../parser/graphql-parser.js";

const GRAPHQL_TYPES = new Set([
  GraphQLQueryParameterType,
  GraphQLVariableParameterType,
]);

class GraphQLTamperPlugin implements Plugin {
  readonly name = "graphql-tamper";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ApplyTamperCommand,
      async (
        cmd: ApplyTamperCommand,
        request: HttpRequest,
      ): Promise<HttpRequest> => {
        const graphqlInstructions = cmd.instructions.filter((instr) =>
          GRAPHQL_TYPES.has(instr.parameter.type),
        );

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
          if (instr.parameter.type === GraphQLQueryParameterType) {
            const field = (instr.parameter.location as { field: string }).field;
            if (typeof jsonBody === "object" && jsonBody !== null && !Array.isArray(jsonBody) && field in jsonBody) {
              (jsonBody as Record<string, JsonValue>)[field] = applyTamperValue(
                (jsonBody as Record<string, JsonValue>)[field],
                instr.payload as string,
                instr.method,
              );
            }
          } else if (instr.parameter.type === GraphQLVariableParameterType) {
            const path = (instr.parameter.location as { path: string[] }).path;
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

export { GraphQLTamperPlugin };
