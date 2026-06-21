import type { MutationType, Payload } from "../../types/branded.ts";
import {
  AuditParameter,
  AuditMutation,
  BuiltinMutationType,
} from "../../types/models.ts";
import { serializable } from "../../types/serializable.ts";
import type { HttpRequest } from "../../types/models.ts";
import type {
  ParserPlugin,
  MutationPlugin,
  PluginContext,
} from "../../core/plugin.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { ApplyMutationCommand } from "../../commands/mutation.ts";

// --- Path Parameter / Mutation ---

export class PathParameter extends AuditParameter<{ name: string }, string> {
  static kind = "path";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): PathMutation {
    return new PathMutation(this, payload, mutationType);
  }
}
serializable(PathParameter);

export class PathMutation extends AuditMutation<PathParameter> {}

// --- Parser ---

/** Lightweight subset of OpenApiOperation used to extract path parameters. */
interface StepOperation {
  path?: string;
  parameters?: Array<{ name: string; in: string }>;
}

interface ScenarioSource {
  steps?: Array<{ operation: StepOperation }>;
}

export class PathParserPlugin implements ParserPlugin {
  readonly name = "parser:path";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      const source = (cmd.scenario as { source?: unknown } | undefined)
        ?.source as ScenarioSource | undefined;
      return parsePathParameters(cmd.request, source);
    });
  }
}

function parsePathParameters(
  request: HttpRequest,
  source?: ScenarioSource,
): PathParameter[] {
  const params: PathParameter[] = [];
  if (!source?.steps?.[0]?.operation?.path) return params;

  const operation = source.steps[0].operation;
  const pathTemplate = operation.path;
  const pathParams = (operation.parameters ?? []).filter(
    (p) => p.in === "path",
  );
  if (pathParams.length === 0) return params;

  const currentPathname = new URL(request.url).pathname;

  for (const paramDef of pathParams) {
    const paramName = paramDef.name;
    const placeholder = `{${paramName}}`;

    // Escape path-template characters then replace {param} with a capture group
    const escapedTemplate = pathTemplate.replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&",
    );
    const regexStr = escapedTemplate.replace(
      `\\{${paramName}\\}`,
      "([^/]+)",
    );
    const regex = new RegExp(regexStr);
    const match = currentPathname.match(regex);

    if (match?.[1]) {
      const currentValue = decodeURIComponent(match[1]);
      params.push(
        new PathParameter({ name: paramName }, currentValue, [
          BuiltinMutationType.ReplaceValue,
          BuiltinMutationType.AppendValue,
          BuiltinMutationType.PrependValue,
        ]),
      );
    }
  }

  return params;
}

// --- Mutation ---

export class PathMutationPlugin implements MutationPlugin {
  readonly name = "mutation:path";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ApplyMutationCommand, async (cmd, request) => {
      const pathMutations = cmd.mutations.filter(
        (instr): instr is PathMutation => instr instanceof PathMutation,
      );
      if (pathMutations.length === 0) return request;

      const url = new URL(request.url);
      let pathname = url.pathname;

      for (const instr of pathMutations) {
        const current = instr.parameter.originalValue;
        const payload = String(instr.payload);
        const modified = applyMutation(current, payload, instr.mutationType);
        // Replace the current (URL-encoded) value with the new one
        pathname = pathname.replace(
          encodeURIComponent(current),
          encodeURIComponent(modified),
        );
      }

      url.pathname = pathname;

      return {
        method: request.method,
        url: url.toString(),
        headers: request.headers,
        body: request.body,
      };
    });
  }
}

function applyMutation(
  current: string,
  payload: string,
  mutationType: MutationType,
): string {
  switch (mutationType) {
    case BuiltinMutationType.ReplaceValue:
      return payload;
    case BuiltinMutationType.AppendValue:
      return current + payload;
    case BuiltinMutationType.PrependValue:
      return payload + current;
    default:
      return current;
  }
}
