import { BuiltinMutationType } from "../../../types/models.ts";
import type {
  AuditParameter,
  HttpRequest,
  JsonValue,
} from "../../../types/models.ts";
import type { ParserPlugin, PluginContext } from "../../../core/plugin.ts";
import { ParseRequestCommand } from "../../../commands/parse-request.ts";
import {
  JsonArrayParameter,
  JsonObjectParameter,
  JsonPrimitiveParameter,
} from "./model.ts";

const ALLOWED_MUTATIONS = [
  BuiltinMutationType.ReplaceValue,
  BuiltinMutationType.AppendValue,
  BuiltinMutationType.PrependValue,
];

export default class JsonParserPlugin implements ParserPlugin {
  readonly name = "parser:json";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseJsonParameters(cmd.request);
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
