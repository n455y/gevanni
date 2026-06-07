import { SignatureGroupId } from "../../types/branded.ts";
import type { Evidence } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

export const NOSQL_ERROR_PATTERNS: RegExp[] = [
  /MongoError/i,
  /Mongo::Error/i,
  /MongoDB.*error/i,
  /mongo.*exception/i,
  /CouchDB.*error/i,
  /Cassandra.*error/i,
  /Invalid BSON/i,
  /BSONError/i,
];

export class NosqlInjectionPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:nosql-injection";
  protected readonly groups = [SignatureGroupId("nosql-injection")];
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const payload = BuiltinPayload.String("' || '1'=='1");
    const instruction = parameter.createMutation(
      payload,
      BuiltinMutationType.AppendValue,
    );
    const result = await replay([instruction]);
    const allExchanges = result.allExchanges;
    const matches = allExchanges.filter((ex) =>
      NOSQL_ERROR_PATTERNS.some((p) =>
        p.test(ex.response.body?.toString() ?? ""),
      ),
    );
    const evidence: Evidence = {
      judgmentId: "nosql-error-pattern",
      exchanges: allExchanges,
      evidenceExchanges: matches,
    };
    return {
      vulnerable: matches.length > 0,
      evidence,
      request: result.exchange.request,
      response: result.exchange.response,
    };
  }
}
