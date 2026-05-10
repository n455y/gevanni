import { AppendValue, Payload as toPayload, Evidence as toEvidence } from "../../types/branded.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";

class ReflectedXssPlugin implements Plugin {
  readonly name = "reflected-xss";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      CreateAuditItemsCommand,
      async (cmd) => {
        return cmd.parameters
          .filter((parameter) => parameter.allowedMutations.includes(AppendValue))
          .map((parameter) => ({
            signatureName: "reflected-xss",
            parameter,
          }));
      },
    );

    context.commandBus.register(
      RunAuditCommand,
      async (cmd) => {
        const { signatureName, parameter, replay } = cmd.context;
        if (signatureName !== "reflected-xss") {
          return null;
        }

        const payload = toPayload("<script>alert(1)</script>");
        const instruction = parameter.createMutation(payload, AppendValue);
        const { request, response } = await replay([instruction]);
        const body = response.body?.toString() ?? "";
        const vulnerable = body.includes(payload);
        return {
          vulnerable,
          evidence: toEvidence(vulnerable
            ? `Payload "${payload}" reflected in response body`
            : `Payload not reflected`),
          request,
          response,
        };
      },
    );
  }
}

export { ReflectedXssPlugin };
