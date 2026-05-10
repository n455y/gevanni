import type { Payload, Evidence } from "../../types/branded.js";
import { AppendValue } from "../../types/branded.js";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import { CreateAuditItemsCommand } from "../../commands/create-audit-items.js";
import { RunAuditCommand } from "../../commands/run-audit.js";

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
      CreateAuditItemsCommand,
      async (cmd) => {
        return cmd.targets
          .filter((param) => param.allowedMutations.includes(AppendValue))
          .map((param) => ({
            signatureName: "sqli-error",
            target: param,
          }));
      },
    );

    context.commandBus.register(
      RunAuditCommand,
      async (cmd) => {
        const { signatureName, target, replay } = cmd.payload;
        if (signatureName !== "sqli-error") {
          throw new Error(`Unknown signature: ${signatureName}`);
        }

        const payload = "' OR 1=1--" as Payload;
        const instruction = target.createMutation(payload, AppendValue);
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
