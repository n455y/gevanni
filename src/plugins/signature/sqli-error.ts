import {
  BuiltinMutationType,
  BuiltinPayload,
  ExchangeId,
  SignatureId,
} from "../../types/branded.ts";
import type { Evidence } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

export const SQL_ERROR_PATTERNS: RegExp[] = [
  /SQL syntax.*MySQL/i,
  /PostgreSQL.*ERROR/i,
  /ORA-\d{5}/i,
  /Microsoft.*ODBC.*SQL Server/i,
  /SQLITE_ERROR/i,
];

export class SqliErrorPlugin extends MutationFilteredSignaturePlugin {
  readonly name = SignatureId("sqli-error");

  constructor() {
    super([BuiltinMutationType.AppendValue]);
  }

  protected async runAudit({ parameter, replay }: RunAuditContext) {
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
  }
}
