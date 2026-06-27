import type { MutationType, Payload } from "../../../types/branded.ts";
import type { JsonValue } from "../../../types/models.ts";
import { AuditMutation, BuiltinMutationType } from "../../../types/models.ts";
import type { MutationPlugin, PluginContext } from "../../../core/plugin.ts";
import { ApplyMutationCommand } from "../../../commands/mutation.ts";
import {
  JsonArrayMutation,
  JsonObjectMutation,
  JsonPrimitiveMutation,
  type JsonMutation,
} from "./model.ts";

function isJsonMutation(instr: AuditMutation): instr is JsonMutation {
  return (
    instr instanceof JsonPrimitiveMutation ||
    instr instanceof JsonArrayMutation ||
    instr instanceof JsonObjectMutation
  );
}

export default class JsonMutationPlugin implements MutationPlugin {
  readonly name = "mutation:json";

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
