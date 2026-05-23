import type {
  MutationType,
  Payload,
} from "../../types/branded.ts";
import type { HttpRequest, JsonValue, JsonObject } from "../../types/models.ts";
import { AuditParameter, AuditMutation, BuiltinMutationType } from "../../types/models.ts";
import { serializable } from "../../types/serializable.ts";
import type { ParserPlugin, MutationPlugin, PluginContext } from "../../core/plugin.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { ApplyMutationCommand } from "../../commands/mutation.ts";

export class GraphQLQueryParameter extends AuditParameter<
  { field: string },
  string
> {
  static kind = "graphql-query";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): GraphQLQueryMutation {
    return new GraphQLQueryMutation(this, payload, mutationType);
  }
}
serializable(GraphQLQueryParameter);

export class GraphQLVariableParameter extends AuditParameter<
  { path: string[] },
  JsonValue
> {
  static kind = "graphql-variable";
  createMutation(
    payload: Payload,
    mutationType: MutationType,
  ): GraphQLVariableMutation {
    return new GraphQLVariableMutation(this, payload, mutationType);
  }
}
serializable(GraphQLVariableParameter);

export class GraphQLQueryMutation extends AuditMutation<GraphQLQueryParameter> {}
export class GraphQLVariableMutation extends AuditMutation<GraphQLVariableParameter> {}

type GraphQLMutation = GraphQLQueryMutation | GraphQLVariableMutation;

function isGraphQLMutation(instr: AuditMutation): instr is GraphQLMutation {
  return (
    instr instanceof GraphQLQueryMutation ||
    instr instanceof GraphQLVariableMutation
  );
}

const ALLOWED_MUTATIONS = [
  BuiltinMutationType.ReplaceValue,
  BuiltinMutationType.AppendValue,
  BuiltinMutationType.PrependValue,
];

export class GraphQLParserPlugin implements ParserPlugin {
  readonly name = "parser:graphql";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseGraphQLParameters(cmd.request);
    });
  }
}

export class GraphQLMutationPlugin implements MutationPlugin {
  readonly name = "mutation:graphql";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ApplyMutationCommand, async (cmd, request) => {
      const graphqlMutations = cmd.mutations.filter(isGraphQLMutation);

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
          const field = instr.parameter.location.field;
          if (
            typeof jsonBody === "object" &&
            jsonBody !== null &&
            !Array.isArray(jsonBody) &&
            field in jsonBody
          ) {
            (jsonBody as Record<string, JsonValue>)[field] = applyMutationValue(
              (jsonBody as Record<string, JsonValue>)[field],
              instr.payload,
              instr.mutationType,
            );
          }
        } else if (instr instanceof GraphQLVariableMutation) {
          const path = instr.parameter.location.path;
          jsonBody = applyAtPath(jsonBody, path, instr.payload, instr.mutationType);
        }
      }

      return {
        method: request.method,
        url: request.url,
        headers: request.headers,
        body: Buffer.from(JSON.stringify(jsonBody), "utf-8"),
      };
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

function applyAtPath(
  root: JsonValue,
  path: string[],
  payload: Payload,
  mutationType: MutationType,
): JsonValue {
  if (path.length === 0) {
    return applyMutationValue(root, payload, mutationType);
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
    copy[index] = applyAtPath(copy[index], path.slice(1), payload, mutationType);
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
    mutationType,
  );
  return copy;
}

function applyMutationValue(
  current: JsonValue,
  payload: Payload,
  mutationType: MutationType,
): JsonValue {
  switch (mutationType) {
    case BuiltinMutationType.ReplaceValue:
      return payload as unknown as JsonValue;
    case BuiltinMutationType.AppendValue:
      return String(current) + String(payload);
    case BuiltinMutationType.PrependValue:
      return String(payload) + String(current);
    default:
      return current;
  }
}
