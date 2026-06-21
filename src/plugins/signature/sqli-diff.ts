import { SignatureGroupId } from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

export class SqliDiffPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:sqli-diff";
  protected readonly groups = [SignatureGroupId("sqli")];
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  protected async runAudit({
    parameter,
    replay,
    scenario,
  }: RunAuditContext) {
    const truePayload = BuiltinPayload.String("' AND 1=1--");
    const trueResult = await replay([
      parameter.createMutation(truePayload, BuiltinMutationType.AppendValue),
    ]);

    const falsePayload = BuiltinPayload.String("' AND 1=2--");
    const falseResult = await replay([
      parameter.createMutation(falsePayload, BuiltinMutationType.AppendValue),
    ]);

    const allExchanges: Exchange[] = [
      ...trueResult.allExchanges,
      ...falseResult.allExchanges,
    ];

    // Exclude JSON-only responses: SQL diff-based payloads on NoSQL endpoints
    // can produce spurious value-level diffs in JSON (e.g. reflected orderId differs)
    const trueCt = trueResult.exchange.response.headers?.["content-type"] ?? "";
    const falseCt = falseResult.exchange.response.headers?.["content-type"] ?? "";
    const bothJson = trueCt.includes("application/json") && falseCt.includes("application/json");

    const judgment = this.compareDiff(
      trueResult.exchange,
      falseResult.exchange,
      scenario.diffStrategy,
    );

    const evidence: Evidence = {
      judgmentId: "diff-based",
      exchanges: allExchanges,
      evidenceExchanges: [trueResult.exchange, falseResult.exchange],
    };
    return {
      vulnerable: judgment.hasDifferent && !bothJson,
      evidence,
      request: trueResult.exchange.request,
      response: trueResult.exchange.response,
    };
  }
}
