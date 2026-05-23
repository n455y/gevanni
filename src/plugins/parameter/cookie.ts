import type { MutationType, Payload } from "../../types/branded.ts";
import { AuditParameter, AuditMutation, BuiltinMutationType } from "../../types/models.ts";
import { serializable } from "../../types/serializable.ts";
import type { HttpRequest } from "../../types/models.ts";
import type { ParserPlugin, MutationPlugin, PluginContext } from "../../core/plugin.ts";
import { ParseRequestCommand } from "../../commands/parse-request.ts";
import { ApplyMutationCommand } from "../../commands/mutation.ts";

export class CookieParameter extends AuditParameter<{ name: string }, string> {
  static kind = "cookie";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): CookieMutation {
    return new CookieMutation(this, payload, mutationType);
  }
}
serializable(CookieParameter);

export class CookieMutation extends AuditMutation<CookieParameter> {}

export class CookieParserPlugin implements ParserPlugin {
  readonly name = "parser:cookie";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ParseRequestCommand, async (cmd) => {
      return parseCookieParameters(cmd.request);
    });
  }
}

export class CookieMutationPlugin implements MutationPlugin {
  readonly name = "mutation:cookie";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(ApplyMutationCommand, async (cmd, request) => {
      const cookieMutations = cmd.mutations.filter(
        (instr): instr is CookieMutation => instr instanceof CookieMutation,
      );

      if (cookieMutations.length === 0) {
        return request;
      }

      const cookies = parseCookieHeader(request.headers["cookie"] ?? "");

      for (const instr of cookieMutations) {
        const cookieName = instr.parameter.location.name;
        const current = cookies.get(cookieName) ?? "";
        const payload = String(instr.payload);
        cookies.set(cookieName, applyMutation(current, payload, instr.mutationType));
      }

      const headers = { ...request.headers };
      const cookieValue = [...cookies.entries()]
        .map(([k, v]) => `${k}=${v}`)
        .join("; ");

      if (cookieValue) {
        headers["cookie"] = cookieValue;
      } else {
        delete headers["cookie"];
      }

      return {
        method: request.method,
        url: request.url,
        headers,
        body: request.body,
      };
    });
  }
}

function parseCookieHeader(header: string): Map<string, string> {
  const cookies = new Map<string, string>();

  for (const pair of header.split(";")) {
    const trimmed = pair.trim();
    if (!trimmed) continue;
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) continue;
    const name = trimmed.slice(0, eqIndex).trim();
    const value = trimmed.slice(eqIndex + 1).trim();
    cookies.set(name, value);
  }

  return cookies;
}

function parseCookieParameters(request: HttpRequest): AuditParameter[] {
  const cookieHeader = request.headers["cookie"];
  if (!cookieHeader) return [];

  const params: AuditParameter[] = [];

  for (const [name, value] of parseCookieHeader(cookieHeader)) {
    params.push(
      new CookieParameter({ name }, value, [
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
    case BuiltinMutationType.PrependValue:
      return payload + current;
    case BuiltinMutationType.AppendValue:
      return current + payload;
    default:
      return current;
  }
}
