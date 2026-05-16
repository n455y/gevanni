import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import {
  BuiltinMutationType,
  BuiltinPayload,
  ExchangeId,
} from "../../types/branded.ts";
import type { Evidence } from "../../types/models.ts";

export const SQL_ERROR_PATTERNS: RegExp[] = [
  /SQL syntax.*MySQL/i,
  /PostgreSQL.*ERROR/i,
  /ORA-\d{5}/i,
  /Microsoft.*ODBC.*SQL Server/i,
  /SQLITE_ERROR/i,
];

export class SqliErrorPlugin implements Plugin {
  readonly name = "sqli-error";

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(CreateAuditItemsCommand, async (cmd) => {
      return cmd.parameters
        .filter((parameter) =>
          parameter.allowedMutations.includes(BuiltinMutationType.AppendValue),
        )
        .map((parameter) => ({
          signatureName: "sqli-error",
          parameter,
        }));
    });

    context.commandBus.register(RunAuditCommand, "sqli-error", async (cmd) => {
      const { parameter, replay } = cmd.context;

      const payload = BuiltinPayload.String("' OR 1=1--");
      const instruction = parameter.createMutation(
        payload,
        BuiltinMutationType.AppendValue,
      );
      const { request, response } = await replay([instruction]);
      const body = response.body?.toString() ?? "";
      const vulnerable = SQL_ERROR_PATTERNS.some((p) => p.test(body));
      const exchange = { id: ExchangeId("ex-0"), request, response };
      const evidence: Evidence = {
        judgmentId: "sql-error-pattern",
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
