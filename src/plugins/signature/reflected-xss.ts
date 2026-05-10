import type { Payload, Evidence } from "../../types/branded.js";
import { AppendValue } from "../../types/branded.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.js";
import { RunAuditCommand } from "../../commands/run-audit.js";

class ReflectedXssPlugin implements Plugin {
  readonly name = "reflected-xss";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      CreateAuditItemsCommand,
      async (cmd) => {
        return cmd.parameters
          .filter((param) => param.allowedMutations.includes(AppendValue))
          .map((param) => ({
            signatureName: "reflected-xss",
            parameter: param,
          }));
      },
    );

    context.commandBus.register(
      RunAuditCommand,
      async (cmd) => {
        const { signatureName, parameter, replay } = cmd.payload;
        if (signatureName !== "reflected-xss") {
          throw new Error(`Unknown signature: ${signatureName}`);
        }

        const payload = "<script>alert(1)</script>" as Payload;
        const instruction = parameter.createMutation(payload, AppendValue);
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
