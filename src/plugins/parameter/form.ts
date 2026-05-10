import {
  MutationType,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.js";
import type { Payload } from "../../types/branded.js";
import { AuditTarget, AuditMutation } from "../../types/models.js";
import { serializable } from "../../types/serializable.js";
import type { HttpRequest } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { ApplyMutationCommand } from "../../commands/mutation.js";

class FormParameter extends AuditTarget<{ name: string }, string> {
  static kind = "form";
  createMutation(
    payload: Payload,
    method: MutationType,
  ): FormMutation {
    return new FormMutation(this, payload, method);
  }
}
serializable(FormParameter);

class FormMutation extends AuditMutation<FormParameter> {}

class FormParserPlugin implements Plugin {
  readonly name = "form-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseFormParameters(cmd.request);
    });
  }
}

class FormMutationPlugin implements Plugin {
  readonly name = "form-mutation";

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
        .filter(
          (instr): instr is FormMutation =>
            instr instanceof FormMutation,
        )
        .filter((instr) => formBody.has(instr.target.location.name));

      if (formMutations.length === 0) {
        return request;
      }

      for (const instr of formMutations) {
        const targetName = instr.target.location.name;
        const current = formBody.get(targetName) ?? "";
        const payload = instr.payload as string;
        const modified = applyMutation(current, payload, instr.method);
        formBody.set(targetName, modified);
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

function parseFormParameters(request: HttpRequest): AuditTarget[] {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return [];
  }

  if (!request.body) {
    return [];
  }

  const searchParams = new URLSearchParams(request.body.toString("utf-8"));
  const params: AuditTarget[] = [];

  for (const [name, value] of searchParams) {
    params.push(
      new FormParameter({ name }, value, [
        ReplaceValue,
        AppendValue,
        PrependValue,
      ]),
    );
  }

  return params;
}

function applyMutation(
  current: string,
  payload: string,
  method: MutationType,
): string {
  switch (method) {
    case ReplaceValue:
      return payload;
    case AppendValue:
      return current + payload;
    case PrependValue:
      return payload + current;
    default:
      return current;
  }
}

export {
  FormParserPlugin,
  FormMutationPlugin,
  FormParameter,
  FormMutation,
};
