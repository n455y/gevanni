import {
  BuiltinMutationType,
  ExchangeId,
  Payload,
} from "../../types/branded.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type { Evidence } from "../../types/models.ts";

export class ReflectedXssPlugin implements Plugin {
  readonly name = "reflected-xss";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(CreateAuditItemsCommand, async (cmd) => {
      return cmd.parameters
        .filter((parameter) =>
          parameter.allowedMutations.includes(BuiltinMutationType.AppendValue),
        )
        .map((parameter) => ({
          signatureName: "reflected-xss",
          parameter,
        }));
    });

    context.commandBus.register(RunAuditCommand, async (cmd) => {
      const { signatureName, parameter, replay } = cmd.context;
      if (signatureName !== "reflected-xss") {
        return null;
      }

      const payload = Payload.string("<script>alert(1)</script>");
      const instruction = parameter.createMutation(
        payload,
        BuiltinMutationType.AppendValue,
      );
      const { request, response } = await replay([instruction]);
      const body = response.body?.toString() ?? "";
      const vulnerable = body.includes(payload);
      const exchange = { id: ExchangeId("ex-0"), request, response };
      const evidence: Evidence = {
        judgmentId: "payload-reflection",
        exchanges: [exchange],
        evidenceExchanges: vulnerable ? [exchange] : [],
      };
      return {
        vulnerable,
        evidence,
        request,
        response,
      };
    });
  }
}
