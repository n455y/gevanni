import { BuiltinMutationType } from "../../types/branded.ts";
import type {
  AnyMutationType,
  MutationType,
  Payload,
} from "../../types/branded.ts";
import { AuditParameter, AuditMutation } from "../../types/models.ts";
import { serializable } from "../../types/serializable.ts";
import type { HttpRequest } from "../../types/models.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { ApplyMutationCommand } from "../../commands/mutation.ts";

export class QueryParameter extends AuditParameter<{ name: string }, string> {
  static kind = "query";
  createMutation<P extends Payload>(
    payload: P,
    method: MutationType<P>,
  ): QueryMutation {
    return new QueryMutation(this, payload, method);
  }
}
serializable(QueryParameter);

export class QueryMutation extends AuditMutation<QueryParameter> {}

export class QueryParserPlugin implements Plugin {
  readonly name = "query-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseQueryParameters(cmd.request);
    });
  }
}

export class QueryMutationPlugin implements Plugin {
  readonly name = "query-mutation";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ApplyMutationCommand, async (cmd, request) => {
      const queryMutations = cmd.mutations.filter(
        (instr): instr is QueryMutation => instr instanceof QueryMutation,
      );

      if (queryMutations.length === 0) {
        return request;
      }

      const url = new URL(request.url);
      const searchParams = new URLSearchParams(url.search);

      for (const instr of queryMutations) {
        const parameterName = instr.parameter.location.name;
        const current = searchParams.get(parameterName) ?? "";
        const payload = String(instr.payload);
        const modified = applyMutation(current, payload, instr.method);
        searchParams.set(parameterName, modified);
      }

      url.search = searchParams.toString();

      return {
        method: request.method,
        url: url.toString(),
        headers: request.headers,
        body: request.body,
      };
    });
  }
}

function parseQueryParameters(request: HttpRequest): AuditParameter[] {
  const url = new URL(request.url);
  const params: AuditParameter[] = [];

  for (const [name, value] of url.searchParams) {
    params.push(
      new QueryParameter({ name }, value, [
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
  method: AnyMutationType,
): string {
  switch (method) {
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
