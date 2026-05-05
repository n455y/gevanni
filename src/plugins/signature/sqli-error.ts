import type { Brand, Payload, Evidence, TamperMethod } from "../../types/branded.js";
import type { InspectionParameter, Finding } from "../../types/models.js";
import type { SignatureInspector, ReplayFn } from "../../core/inspector.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { CreateInspectorsCommand } from "../../commands/create-inspectors.js";

const SQL_ERROR_PATTERNS: RegExp[] = [
  /SQL syntax.*MySQL/i,
  /PostgreSQL.*ERROR/i,
  /ORA-\d{5}/i,
  /Microsoft.*ODBC.*SQL Server/i,
  /SQLITE_ERROR/i,
];

class SqliErrorInspector implements SignatureInspector {
  readonly signatureName = "sqli-error";
  readonly parameters: InspectionParameter[];

  constructor(private param: InspectionParameter) {
    this.parameters = [param];
  }

  async inspect(replay: ReplayFn): Promise<Finding> {
    const payload = "' OR 1=1--" as Payload;
    const instruction = {
      parameter: this.param,
      payload,
      method: "appendValue" as TamperMethod,
    };
    const { request, response } = await replay([instruction]);
    const body = response.body?.toString() ?? "";
    const vulnerable = SQL_ERROR_PATTERNS.some((p) => p.test(body));
    return {
      vulnerable,
      evidence: (vulnerable
        ? `SQL error pattern detected in response`
        : `No SQL error pattern detected`) as Evidence,
      request,
      response,
    };
  }
}

class SqliErrorPlugin implements Plugin {
  readonly name = "sqli-error";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      CreateInspectorsCommand,
      async (cmd: CreateInspectorsCommand) => {
        const inspectors: SignatureInspector[] = [];
        for (const param of cmd.parameters) {
          if (
            param.type === ("query" as Brand<"query", "ParameterType">) ||
            param.type === ("jsonPrimitive" as Brand<"jsonPrimitive", "ParameterType">)
          ) {
            inspectors.push(new SqliErrorInspector(param));
          }
        }
        return inspectors;
      },
    );
  }
}

export { SqliErrorInspector, SQL_ERROR_PATTERNS, SqliErrorPlugin };
