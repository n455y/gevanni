import {
  MutationType,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.js";
import type { Payload } from "../../types/branded.js";
import type { HttpRequest, JsonValue, JsonObject } from "../../types/models.js";
import { AuditTarget, AuditMutation } from "../../types/models.js";
import { serializable } from "../../types/serializable.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { ApplyMutationCommand } from "../../commands/mutation.js";

@serializable
class GraphQLQueryParameter extends AuditTarget<
  { field: string },
  string
> {
  static kind = "graphql-query";
  createMutation(
    payload: Payload,
    method: MutationType,
  ): GraphQLQueryMutation {
    return new GraphQLQueryMutation(this, payload, method);
  }
}
@serializable
class GraphQLVariableParameter extends AuditTarget<
  { path: string[] },
  JsonValue
> {
  static kind = "graphql-variable";
  createMutation(
    payload: Payload,
    method: MutationType,
  ): GraphQLVariableMutation {
    return new GraphQLVariableMutation(this, payload, method);
  }
}

class GraphQLQueryMutation extends AuditMutation<GraphQLQueryParameter> {}
class GraphQLVariableMutation extends AuditMutation<GraphQLVariableParameter> {}

type GraphQLMutation =
  | GraphQLQueryMutation
  | GraphQLVariableMutation;

function isGraphQLMutation(
  instr: AuditMutation,
): instr is GraphQLMutation {
  return (
    instr instanceof GraphQLQueryMutation ||
    instr instanceof GraphQLVariableMutation
  );
}

const ALLOWED_MUTATIONS = [ReplaceValue, AppendValue, PrependValue];

class GraphQLParserPlugin implements Plugin {
  readonly name = "graphql-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ParseRequestCommand,
      async (cmd) => {
        return parseGraphQLParameters(cmd.request);
      },
    );
  }
}

class GraphQLMutationPlugin implements Plugin {
  readonly name = "graphql-mutation";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ApplyMutationCommand,
      async (cmd, request) => {
        const graphqlMutations =
          cmd.mutations.filter(isGraphQLMutation);

        if (graphqlMutations.length === 0) {
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

        for (const instr of graphqlMutations) {
          if (instr instanceof GraphQLQueryMutation) {
            const field = instr.target.location.field;
            if (
              typeof jsonBody === "object" &&
              jsonBody !== null &&
              !Array.isArray(jsonBody) &&
              field in jsonBody
            ) {
              (jsonBody as Record<string, JsonValue>)[field] = applyMutationValue(
                (jsonBody as Record<string, JsonValue>)[field],
                instr.payload as string,
                instr.method,
              );
            }
          } else if (instr instanceof GraphQLVariableMutation) {
            const path = instr.target.location.path;
            jsonBody = applyAtPath(
              jsonBody,
              path,
              instr.payload as string,
              instr.method,
            );
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

function parseGraphQLParameters(request: HttpRequest): AuditTarget[] {
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

  const params: AuditTarget[] = [];

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
  params: AuditTarget[],
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

function applyAtPath(
  root: JsonValue,
  path: string[],
  payload: string,
  method: MutationType,
): JsonValue {
  if (path.length === 0) {
    return applyMutationValue(root, payload, method);
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
  copy[key] = applyAtPath(
    copy[key] as JsonValue,
    path.slice(1),
    payload,
    method,
  );
  return copy;
}

function applyMutationValue(
  current: JsonValue,
  payload: string,
  method: MutationType,
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

export {
  GraphQLParserPlugin,
  GraphQLMutationPlugin,
  GraphQLQueryParameter,
  GraphQLVariableParameter,
  GraphQLQueryMutation,
  GraphQLVariableMutation,
};
