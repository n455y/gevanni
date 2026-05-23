import type {
  MutationType,
  Payload,
} from "../../types/branded.ts";
import { AuditParameter, AuditMutation, BuiltinMutationType } from "../../types/models.ts";
import { serializable } from "../../types/serializable.ts";
import type { HttpRequest } from "../../types/models.ts";
import type { ParserPlugin, MutationPlugin, PluginContext } from "../../core/plugin.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { ApplyMutationCommand } from "../../commands/mutation.ts";

export class FormParameter extends AuditParameter<{ name: string }, string> {
  static kind = "form";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): FormMutation {
    return new FormMutation(this, payload, mutationType);
  }
}
serializable(FormParameter);

export class FormMutation extends AuditMutation<FormParameter> {}

export class FormParserPlugin implements ParserPlugin {
  readonly name = "parser:form";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseFormParameters(cmd.request);
    });
  }
}

export class FormMutationPlugin implements MutationPlugin {
  readonly name = "mutation:form";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ApplyMutationCommand, async (cmd, request) => {
      const contentType = request.headers["content-type"] ?? "";
      if (!contentType.includes("application/x-www-form-urlencoded")) {
        return request;
      }

      if (!request.body) {
        return request;
      }

      const formBody = new URLSearchParams(request.body.toString("utf-8"));

      const formMutations = cmd.mutations
        .filter((instr): instr is FormMutation => instr instanceof FormMutation)
        .filter((instr) => formBody.has(instr.parameter.location.name));

      if (formMutations.length === 0) {
        return request;
      }

      for (const instr of formMutations) {
        const parameterName = instr.parameter.location.name;
        const current = formBody.get(parameterName) ?? "";
        const payload = String(instr.payload);
        const modified = applyMutation(current, payload, instr.mutationType);
        formBody.set(parameterName, modified);
      }

      return {
        method: request.method,
        url: request.url,
        headers: request.headers,
        body: Buffer.from(formBody.toString(), "utf-8"),
      };
    });
  }
}

function parseFormParameters(request: HttpRequest): AuditParameter[] {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return [];
  }

  if (!request.body) {
    return [];
  }

  const searchParams = new URLSearchParams(request.body.toString("utf-8"));
  const params: AuditParameter[] = [];

  for (const [name, value] of searchParams) {
    params.push(
      new FormParameter({ name }, value, [
        BuiltinMutationType.ReplaceValue,
        BuiltinMutationType.AppendValue,
        BuiltinMutationType.PrependValue,
      ]),
    );
  }

  return params;
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
