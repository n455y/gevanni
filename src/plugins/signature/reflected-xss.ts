import type { Payload, Evidence } from "../../types/branded.js";
import { AppendValue } from "../../types/branded.js";
import type { InspectionParameter, Finding } from "../../types/models.js";
import { TamperInstruction } from "../../types/models.js";
import type { SignatureInspector, ReplayFn } from "../../core/inspector.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { CreateInspectorsCommand } from "../../commands/create-inspectors.js";

class ReflectedXssInspector implements SignatureInspector {
  readonly signatureName = "reflected-xss";
  readonly parameters: InspectionParameter<unknown, unknown>[];

  constructor(private param: InspectionParameter<unknown, unknown>) {
    this.parameters = [param];
  }

  async inspect(replay: ReplayFn): Promise<Finding> {
    const payload = "<script>alert(1)</script>" as Payload;
    const instruction = new TamperInstruction(
      this.param,
      payload,
      AppendValue,
    );
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
  }
}

class ReflectedXssPlugin implements Plugin {
  readonly name = "reflected-xss";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      CreateInspectorsCommand,
      async (cmd: CreateInspectorsCommand) => {
        return cmd.parameters
          .filter((p) => p.allowedTampers.includes(AppendValue))
          .map((p) => new ReflectedXssInspector(p));
      },
    );
  }
}

export { ReflectedXssInspector, ReflectedXssPlugin };
