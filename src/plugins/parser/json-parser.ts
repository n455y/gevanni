import { ParameterType, ReplaceValue, AppendValue, PrependValue } from "../../types/branded.js";
import type {
  HttpRequest,
  InspectionParameter,
  JsonPrimitive,
  JsonArray,
  JsonObject,
  JsonValue,
} from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";

class JsonPrimitiveParameterType extends ParameterType {}
class JsonArrayParameterType extends ParameterType {}
class JsonObjectParameterType extends ParameterType {}

type JsonPrimitiveParameter = InspectionParameter<typeof JsonPrimitiveParameterType, { path: string[] }, JsonPrimitive>;
type JsonArrayParameter = InspectionParameter<typeof JsonArrayParameterType, { path: string[] }, JsonArray>;
type JsonObjectParameter = InspectionParameter<typeof JsonObjectParameterType, { path: string[] }, JsonObject>;

const ALLOWED_TAMPERS = [
  ReplaceValue,
  AppendValue,
  PrependValue,
];

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

function parseJsonParameters(
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

  const params: InspectionParameter[] = [];
  extractJsonParams(parsed, [], params);
  return params;
}

function extractJsonParams(
  value: JsonValue,
  path: string[],
  params: InspectionParameter[],
): void {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    params.push({
      type: JsonPrimitiveParameterType,
      location: { path },
      originalValue: value as JsonPrimitive,
      allowedTampers: [...ALLOWED_TAMPERS],
    } satisfies JsonPrimitiveParameter);
  } else if (Array.isArray(value)) {
    params.push({
      type: JsonArrayParameterType,
      location: { path },
      originalValue: value as JsonArray,
      allowedTampers: [...ALLOWED_TAMPERS],
    } satisfies JsonArrayParameter);

    for (let i = 0; i < value.length; i++) {
      extractJsonParams(value[i], [...path, String(i)], params);
    }
  } else if (typeof value === "object") {
    params.push({
      type: JsonObjectParameterType,
      location: { path },
      originalValue: value as JsonObject,
      allowedTampers: [...ALLOWED_TAMPERS],
    } satisfies JsonObjectParameter);

    for (const key of Object.keys(value)) {
      extractJsonParams(value[key], [...path, key], params);
    }
  }
}

export { JsonParserPlugin, JsonPrimitiveParameterType, JsonArrayParameterType, JsonObjectParameterType };
export type { JsonPrimitiveParameter, JsonArrayParameter, JsonObjectParameter };
