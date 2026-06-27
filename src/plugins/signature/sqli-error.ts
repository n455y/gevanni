import { SignatureGroupId } from "../../types/branded.ts";
import type { Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

export const SQL_ERROR_PATTERNS: RegExp[] = [
  /SQL syntax.*MySQL/i,
  /PostgreSQL.*ERROR/i,
  /ORA-\d{5}/i,
  /Microsoft.*ODBC.*SQL Server/i,
  /SQLITE_ERROR/i,
];

export default class SqliErrorPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:sqli-error";
  protected readonly groups = [SignatureGroupId("sqli")];
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  protected async runAudit({
    parameter,
    replay,
    scenario,
  }: RunAuditContext) {
    const safePayload = BuiltinPayload.String("''");
    const safeResult = await replay([
      parameter.createMutation(safePayload, BuiltinMutationType.AppendValue),
    ]);

    const unsafePayload = BuiltinPayload.String("'''");
    const unsafeResult = await replay([
      parameter.createMutation(unsafePayload, BuiltinMutationType.AppendValue),
    ]);

    const allExchanges: Exchange[] = [
      ...safeResult.allExchanges,
      ...unsafeResult.allExchanges,
    ];

    const matches = allExchanges.filter((ex) =>
      SQL_ERROR_PATTERNS.some((p) =>
        p.test(ex.response.body?.toString() ?? ""),
      ),
    );

    if (matches.length > 0) {
      return {
        vulnerable: true,
        evidence: {
          judgmentId: "sql-error-pattern",
          exchanges: allExchanges,
          evidenceExchanges: matches,
        },
        request: unsafeResult.exchange.request,
        response: unsafeResult.exchange.response,
      };
    }

    const judgment = this.compareDiff(
      safeResult.exchange,
      unsafeResult.exchange,
      scenario.diffStrategy,
    );

    return {
      vulnerable: judgment.hasDifferent,
      evidence: {
        judgmentId: "diff-based",
        exchanges: allExchanges,
        evidenceExchanges: [safeResult.exchange, unsafeResult.exchange],
      },
      request: unsafeResult.exchange.request,
      response: unsafeResult.exchange.response,
    };
  }
}
