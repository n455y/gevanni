import { SignatureGroupId } from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

/**
 * NoSQL boolean-based blind injection detection.
 * Uses true/false payloads and compares response body / status code.
 *
 * True payload:  ' || '1'=='1  → should return data
 * False payload: ' || '1'=='2  → should return empty
 */
export class NosqlBooleanPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:nosql-boolean";
  protected readonly groups = [SignatureGroupId("nosql-injection")];
  protected readonly mutationTypes = [
    BuiltinMutationType.ReplaceValue,
    BuiltinMutationType.AppendValue,
  ] as const;

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const truePayload = BuiltinPayload.String("' || '1'=='1");
    const falsePayload = BuiltinPayload.String("' || '1'=='2");

    // Try both AppendValue (for query/header/cookie params) and
    // ReplaceValue (for path params where AppendValue would break integer IDs)
    for (const mutationType of [BuiltinMutationType.AppendValue, BuiltinMutationType.ReplaceValue]) {
      const trueResult = await replay([
        parameter.createMutation(truePayload, mutationType),
      ]);
      const falseResult = await replay([
        parameter.createMutation(falsePayload, mutationType),
      ]);

      const trueBody = trueResult.exchange.response.body?.toString() ?? "";
      const falseBody = falseResult.exchange.response.body?.toString() ?? "";
      const trueStatus = trueResult.exchange.response.statusCode;
      const falseStatus = falseResult.exchange.response.statusCode;

      const allExchanges: Exchange[] = [
        ...trueResult.allExchanges,
        ...falseResult.allExchanges,
      ];
      const vulnerable = trueBody !== falseBody || trueStatus !== falseStatus;

      if (vulnerable) {
        const evidence: Evidence = {
          judgmentId: "nosql-boolean-differential",
          exchanges: allExchanges,
          evidenceExchanges: [trueResult.exchange, falseResult.exchange],
        };
        return {
          vulnerable,
          evidence,
          request: trueResult.exchange.request,
          response: trueResult.exchange.response,
        };
      }
    }

    // Neither mutation type detected a difference
    return {
      vulnerable: false,
      evidence: {
        judgmentId: "nosql-boolean-differential",
        exchanges: [],
        evidenceExchanges: [],
      },
      request: { method: "GET", url: "", headers: {}, body: null },
      response: { statusCode: 0, headers: {}, body: null },
    };
  }
}
