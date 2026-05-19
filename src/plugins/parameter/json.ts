import type {
  MutationType,
  Payload,
} from "../../types/branded.ts";
import type {
  HttpRequest,
  JsonPrimitive,
  JsonArray,
  JsonObject,
  JsonValue,
} from "../../types/models.ts";
import { AuditParameter, AuditMutation, BuiltinMutationType } from "../../types/models.ts";
import { serializable } from "../../types/serializable.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { ApplyMutationCommand } from "../../commands/mutation.ts";

export class JsonPrimitiveParameter extends AuditParameter<
  { path: string[] },
  JsonPrimitive
> {
  static kind = "json-primitive";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): JsonPrimitiveMutation {
    return new JsonPrimitiveMutation(this, payload, mutationType);
  }
}
serializable(JsonPrimitiveParameter);

export class JsonArrayParameter extends AuditParameter<
  { path: string[] },
  JsonArray
> {
  static kind = "json-array";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): JsonArrayMutation {
    return new JsonArrayMutation(this, payload, mutationType);
  }
}
serializable(JsonArrayParameter);

export class JsonObjectParameter extends AuditParameter<
  { path: string[] },
  JsonObject
> {
  static kind = "json-object";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): JsonObjectMutation {
    return new JsonObjectMutation(this, payload, mutationType);
  }
}
serializable(JsonObjectParameter);

export class JsonPrimitiveMutation extends AuditMutation<JsonPrimitiveParameter> {}
export class JsonArrayMutation extends AuditMutation<JsonArrayParameter> {}
export class JsonObjectMutation extends AuditMutation<JsonObjectParameter> {}

type JsonMutation =
  | JsonPrimitiveMutation
  | JsonArrayMutation
  | JsonObjectMutation;

const ALLOWED_MUTATIONS = [
  BuiltinMutationType.ReplaceValue,
  BuiltinMutationType.AppendValue,
  BuiltinMutationType.PrependValue,
];

function isJsonMutation(instr: AuditMutation): instr is JsonMutation {
  return (
    instr instanceof JsonPrimitiveMutation ||
    instr instanceof JsonArrayMutation ||
    instr instanceof JsonObjectMutation
  );
}

export class JsonParserPlugin implements Plugin {
  readonly name = "json-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseJsonParameters(cmd.request);
    });
  }
}

export class JsonMutationPlugin implements Plugin {
  readonly name = "json-mutation";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ApplyMutationCommand, async (cmd, request) => {
      const jsonMutations = cmd.mutations.filter(isJsonMutation);

      if (jsonMutations.length === 0) {
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

      for (const instr of jsonMutations) {
        const path = instr.parameter.location.path;
        jsonBody = applyAtPath(jsonBody, path, instr.payload, instr.mutationType);
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

function parseJsonParameters(request: HttpRequest): AuditParameter[] {
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

  const params: AuditParameter[] = [];
  extractJsonParams(parsed, [], params);
  return params;
}

function extractJsonParams(
  value: JsonValue,
  path: string[],
  params: AuditParameter[],
): void {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    params.push(
      new JsonPrimitiveParameter({ path }, value, [...ALLOWED_MUTATIONS]),
    );
  } else if (Array.isArray(value)) {
    params.push(
      new JsonArrayParameter({ path }, value, [...ALLOWED_MUTATIONS]),
    );

    for (let i = 0; i < value.length; i++) {
      extractJsonParams(value[i], [...path, String(i)], params);
    }
  } else if (typeof value === "object") {
    params.push(
      new JsonObjectParameter({ path }, value, [...ALLOWED_MUTATIONS]),
    );

    for (const key of Object.keys(value)) {
      extractJsonParams(value[key], [...path, key], params);
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
