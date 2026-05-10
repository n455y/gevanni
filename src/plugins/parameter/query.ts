import {
  MutationType,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.js";
import type { Payload } from "../../types/branded.js";
import { AuditTarget, AuditMutation } from "../../types/models.js";
import type { HttpRequest } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";

class QueryParameter extends AuditTarget<{ name: string }, string> {
  createMutation(
    payload: Payload,
    method: MutationType,
  ): QueryMutation {
    return new QueryMutation(this, payload, method);
  }
}

class QueryMutation extends AuditMutation<QueryParameter> {}

class QueryParserPlugin implements Plugin {
  readonly name = "query-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ParseRequestCommand,
      async (cmd) => {
        return parseQueryParameters(cmd.request);
      },
    );
  }
}

class QueryTamperPlugin implements Plugin {
  readonly name = "query-tamper";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ApplyTamperCommand,
      async (cmd, request) => {
        const queryInstructions = cmd.instructions.filter(
          (instr): instr is QueryMutation =>
            instr instanceof QueryMutation,
        );

        if (queryInstructions.length === 0) {
          return request;
        }

        const url = new URL(request.url);
        const searchParams = new URLSearchParams(url.search);

        for (const instr of queryInstructions) {
          const paramName = instr.parameter.location.name;
          const current = searchParams.get(paramName) ?? "";
          const payload = instr.payload as string;
          const modified = applyTamper(current, payload, instr.method);
          searchParams.set(paramName, modified);
        }

        url.search = searchParams.toString();

        return {
          method: request.method,
          url: url.toString(),
          headers: request.headers,
          body: request.body,
        };
      },
    );
  }
}

function parseQueryParameters(request: HttpRequest): AuditTarget[] {
  const url = new URL(request.url);
  const params: AuditTarget[] = [];

  for (const [name, value] of url.searchParams) {
    params.push(
      new QueryParameter({ name }, value, [
        ReplaceValue,
        AppendValue,
        PrependValue,
      ]),
    );
  }

  return params;
}

function applyTamper(
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
  QueryParserPlugin,
  QueryTamperPlugin,
  QueryParameter,
  QueryMutation,
};
