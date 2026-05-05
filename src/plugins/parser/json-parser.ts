import type { Brand, TamperMethod } from "../../types/branded.js";
import type {
  HttpRequest,
  InspectionParameter,
  JsonPrimitive,
  JsonArray,
  JsonObject,
  JsonValue,
  JsonPrimitiveParameter,
  JsonArrayParameter,
  JsonObjectParameter,
} from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";

const ALLOWED_TAMPERS: TamperMethod[] = [
  "replaceValue" as TamperMethod,
  "appendValue" as TamperMethod,
  "prependValue" as TamperMethod,
];

function createJsonParserPlugin(): Plugin {
  return {
    name: "json-parser",

    async init(context: PluginContext): Promise<void> {
      context.commandBus.register(
        ParseRequestCommand,
        async (cmd: ParseRequestCommand) => {
          return parseJsonParameters(cmd.request);
        },
      );
    },
  };
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
      type: "jsonPrimitive" as Brand<"jsonPrimitive", "ParameterType">,
      location: { path },
      originalValue: value as JsonPrimitive,
      allowedTampers: [...ALLOWED_TAMPERS],
    } satisfies JsonPrimitiveParameter);
  } else if (Array.isArray(value)) {
    params.push({
      type: "jsonArray" as Brand<"jsonArray", "ParameterType">,
      location: { path },
      originalValue: value as JsonArray,
      allowedTampers: [...ALLOWED_TAMPERS],
    } satisfies JsonArrayParameter);

    for (let i = 0; i < value.length; i++) {
      extractJsonParams(value[i], [...path, String(i)], params);
    }
  } else if (typeof value === "object") {
    params.push({
      type: "jsonObject" as Brand<"jsonObject", "ParameterType">,
      location: { path },
      originalValue: value as JsonObject,
      allowedTampers: [...ALLOWED_TAMPERS],
    } satisfies JsonObjectParameter);

    for (const key of Object.keys(value)) {
      extractJsonParams(value[key], [...path, key], params);
    }
  }
}

export { createJsonParserPlugin };
