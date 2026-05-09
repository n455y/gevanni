import type { Payload, Evidence } from "../../types/branded.js";
import { AppendValue } from "../../types/branded.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { CreateInspectorsCommand } from "../../commands/create-inspectors.js";
import { RunInspectionCommand } from "../../commands/run-inspection.js";

const SQL_ERROR_PATTERNS: RegExp[] = [
  /SQL syntax.*MySQL/i,
  /PostgreSQL.*ERROR/i,
  /ORA-\d{5}/i,
  /Microsoft.*ODBC.*SQL Server/i,
  /SQLITE_ERROR/i,
];

class SqliErrorPlugin implements Plugin {
  readonly name = "sqli-error";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(
      CreateInspectorsCommand,
      async (cmd) => {
        return cmd.parameters
          .filter((param) => param.allowedTampers.includes(AppendValue))
          .map((param) => ({
            signatureName: "sqli-error",
            parameter: param,
          }));
      },
    );

    context.commandBus.register(
      RunInspectionCommand,
      async (cmd) => {
        const { signatureName, parameter, replay } = cmd.payload;
        if (signatureName !== "sqli-error") {
          throw new Error(`Unknown signature: ${signatureName}`);
        }

        const payload = "' OR 1=1--" as Payload;
        const instruction = parameter.createInstruction(payload, AppendValue);
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
      },
    );
  }
}

export { SqliErrorPlugin, SQL_ERROR_PATTERNS };
