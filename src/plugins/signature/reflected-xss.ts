import type { Payload, Evidence } from "../../types/branded.ts";
import { AppendValue } from "../../types/branded.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";

class ReflectedXssPlugin implements Plugin {
  readonly name = "reflected-xss";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      CreateAuditItemsCommand,
      async (cmd) => {
        return cmd.targets
          .filter((target) => target.allowedMutations.includes(AppendValue))
          .map((target) => ({
            signatureName: "reflected-xss",
            target,
          }));
      },
    );

    context.commandBus.register(
      RunAuditCommand,
      async (cmd) => {
        const { signatureName, target, replay } = cmd.payload;
        if (signatureName !== "reflected-xss") {
          throw new Error(`Unknown signature: ${signatureName}`);
        }

        const payload = "<script>alert(1)</script>" as Payload;
        const instruction = target.createMutation(payload, AppendValue);
        const { request, response } = await replay([instruction]);
        const body = response.body?.toString() ?? "";
        const vulnerable = body.includes(payload);
        return {
          vulnerable,
          evidence: (vulnerable
            ? `Payload "${payload}" reflected in response body`
            : `Payload not reflected`) as Evidence,
          request,
          response,
        };
      },
    );
  }
}

export { ReflectedXssPlugin };
