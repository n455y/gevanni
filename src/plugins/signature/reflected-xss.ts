import type { Payload, Evidence, TamperMethod } from "../../types/branded.js";
import type { InspectionParameter, Finding } from "../../types/models.js";
import type { SignatureInspector, ReplayFn } from "../../core/inspector.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { CreateInspectorsCommand } from "../../commands/create-inspectors.js";
import { QueryParameterType } from "../parser/query-parser.js";
import { FormParameterType } from "../parser/form-parser.js";
import { JsonPrimitiveParameterType } from "../parser/json-parser.js";

class ReflectedXssInspector implements SignatureInspector {
  readonly signatureName = "reflected-xss";
  readonly parameters: InspectionParameter[];

  constructor(private param: InspectionParameter) {
    this.parameters = [param];
  }

  async inspect(replay: ReplayFn): Promise<Finding> {
    const payload = '<script>alert(1)</script>' as Payload;
    const instruction = {
      parameter: this.param,
      payload,
      method: "replaceValue" as TamperMethod,
    };
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
        const inspectors: SignatureInspector[] = [];
        for (const param of cmd.parameters) {
          if (
            param.type === QueryParameterType ||
            param.type === JsonPrimitiveParameterType ||
            param.type === FormParameterType
          ) {
            inspectors.push(new ReflectedXssInspector(param));
          }
        }
        return inspectors;
      },
    );
  }
}

export { ReflectedXssInspector, ReflectedXssPlugin };
