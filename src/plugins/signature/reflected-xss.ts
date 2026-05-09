import type { Payload, Evidence } from "../../types/branded.js";
import { AppendValue } from "../../types/branded.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { CreateInspectorsCommand } from "../../commands/create-inspectors.js";
import { RunInspectionCommand } from "../../commands/run-inspection.js";

class ReflectedXssPlugin implements Plugin {
  readonly name = "reflected-xss";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      CreateInspectorsCommand,
      async (cmd) => {
        return cmd.parameters
          .filter((param) => param.allowedTampers.includes(AppendValue))
          .map((param) => ({
            signatureName: "reflected-xss",
            parameter: param,
          }));
      },
    );

    context.commandBus.register(
      RunInspectionCommand,
      async (cmd) => {
        const { signatureName, parameter, replay } = cmd.payload;
        if (signatureName !== "reflected-xss") {
          throw new Error(`Unknown signature: ${signatureName}`);
        }

        const payload = "<script>alert(1)</script>" as Payload;
        const instruction = parameter.createInstruction(payload, AppendValue);
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
