import { TamperMethod, ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";
import type {
  HttpRequest,
  TamperInstruction,
  JsonValue,
} from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";
import { JsonPrimitiveParameterType, JsonArrayParameterType, JsonObjectParameterType } from "../parser/json-parser.js";

const JSON_TYPES = new Set([
  JsonPrimitiveParameterType,
  JsonArrayParameterType,
  JsonObjectParameterType,
]);

class JsonTamperPlugin implements Plugin {
  readonly name = "json-tamper";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ApplyTamperCommand,
      async (
        cmd: ApplyTamperCommand,
        request: HttpRequest,
      ): Promise<HttpRequest> => {
        const jsonInstructions = cmd.instructions.filter((instr) =>
          JSON_TYPES.has(instr.parameter.type),
        );

        if (jsonInstructions.length === 0) {
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

        for (const instr of jsonInstructions) {
          const path = (instr.parameter.location as { path: string[] }).path;
          jsonBody = applyAtPath(jsonBody, path, instr.payload, instr.method);
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

export { JsonTamperPlugin };
