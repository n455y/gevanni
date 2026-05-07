import { TamperMethod, ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";
import type {
  HttpRequest,
  InspectionParameter,
  JsonPrimitive,
  JsonArray,
  JsonObject,
  JsonValue,
} from "../../types/models.js";
import {
  JsonPrimitiveParameter,
  JsonArrayParameter,
  JsonObjectParameter,
  JsonPrimitiveTamperInstruction,
  JsonArrayTamperInstruction,
  JsonObjectTamperInstruction,
  TamperInstruction,
} from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";

type JsonTamperInstruction = JsonPrimitiveTamperInstruction | JsonArrayTamperInstruction | JsonObjectTamperInstruction;

const ALLOWED_TAMPERS = [ReplaceValue, AppendValue, PrependValue];

function isJsonInstruction(instr: TamperInstruction): instr is JsonTamperInstruction {
  return instr instanceof JsonPrimitiveTamperInstruction
    || instr instanceof JsonArrayTamperInstruction
    || instr instanceof JsonObjectTamperInstruction;
}

class JsonParserPlugin implements Plugin {
  readonly name = "json-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ParseRequestCommand,
      async (cmd: ParseRequestCommand) => {
        return parseJsonParameters(cmd.request);
      },
    );
  }
}

class JsonTamperPlugin implements Plugin {
  readonly name = "json-tamper";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ApplyTamperCommand,
      async (
        cmd: ApplyTamperCommand,
        request: HttpRequest,
      ): Promise<HttpRequest> => {
        const jsonInstructions = cmd.instructions.filter(isJsonInstruction);

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
          const path = instr.parameter.location.path;
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

function parseJsonParameters(
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

  const params: InspectionParameter<unknown, unknown>[] = [];
  extractJsonParams(parsed, [], params);
  return params;
}

function extractJsonParams(
  value: JsonValue,
  path: string[],
  params: InspectionParameter<unknown, unknown>[],
): void {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    params.push(new JsonPrimitiveParameter(
      { path },
      value,
      [...ALLOWED_TAMPERS],
    ));
  } else if (Array.isArray(value)) {
    params.push(new JsonArrayParameter(
      { path },
      value,
      [...ALLOWED_TAMPERS],
    ));

    for (let i = 0; i < value.length; i++) {
      extractJsonParams(value[i], [...path, String(i)], params);
    }
  } else if (typeof value === "object") {
    params.push(new JsonObjectParameter(
      { path },
      value,
      [...ALLOWED_TAMPERS],
    ));

    for (const key of Object.keys(value)) {
      extractJsonParams(value[key], [...path, key], params);
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

export { JsonParserPlugin, JsonTamperPlugin };
