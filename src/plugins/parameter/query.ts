import {
  TamperMethod,
  ReplaceValue,
  AppendValue,
  PrependValue,
} from "../../types/branded.js";
import type { Payload } from "../../types/branded.js";
import { InspectionParameter, TamperInstruction } from "../../types/models.js";
import type { HttpRequest } from "../../types/models.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { ParseRequestCommand } from "../../commands/parse-request.js";
import { ApplyTamperCommand } from "../../commands/tamper.js";

class QueryParameter extends InspectionParameter<{ name: string }, string> {
  createInstruction(
    payload: Payload,
    method: TamperMethod,
  ): QueryTamperInstruction {
    return new QueryTamperInstruction(this, payload, method);
  }
}

class QueryTamperInstruction extends TamperInstruction<QueryParameter> {}

class QueryParserPlugin implements Plugin {
  readonly name = "query-parser";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      ParseRequestCommand,
      async (cmd: ParseRequestCommand) => {
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
      async (
        cmd: ApplyTamperCommand,
        request: HttpRequest,
      ): Promise<HttpRequest> => {
        const queryInstructions = cmd.instructions.filter(
          (instr): instr is QueryTamperInstruction =>
            instr instanceof QueryTamperInstruction,
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

function parseQueryParameters(
  request: HttpRequest,
): InspectionParameter<unknown, unknown>[] {
  const url = new URL(request.url);
  const params: InspectionParameter<unknown, unknown>[] = [];

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
  method: TamperMethod,
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
  QueryTamperInstruction,
};
