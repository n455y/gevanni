import { SignatureGroupId } from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

/**
 * NoSQL diff-based injection detection.
 * Uses true/false payloads and compares responses with the scenario's diff strategy.
 *
 * True payload:  ' || '1'=='1  → should return data
 * False payload: ' || '1'=='2  → should return empty
 */
export default class NosqlDiffPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:nosql-diff";
  protected readonly groups = [SignatureGroupId("nosql-injection")];
  protected readonly mutationTypes = [
    BuiltinMutationType.ReplaceValue,
    BuiltinMutationType.AppendValue,
  ] as const;

  protected async runAudit({
    parameter,
    replay,
    scenario,
  }: RunAuditContext) {
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

      const allExchanges: Exchange[] = [
        ...trueResult.allExchanges,
        ...falseResult.allExchanges,
      ];

      const judgment = this.compareDiff(
        trueResult.exchange,
        falseResult.exchange,
        scenario.diffStrategy,
      );

      if (judgment.hasDifferent) {
        const evidence: Evidence = {
          judgmentId: "nosql-diff-based",
          exchanges: allExchanges,
          evidenceExchanges: [trueResult.exchange, falseResult.exchange],
        };
        return {
          vulnerable: true,
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
        judgmentId: "nosql-diff-based",
        exchanges: [],
        evidenceExchanges: [],
      },
      request: { method: "GET", url: "", headers: {}, body: null },
      response: { statusCode: 0, headers: {}, body: null },
    };
  }
}
