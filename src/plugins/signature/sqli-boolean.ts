import {
  SignatureGroupId,
  SignatureId,
} from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

export class SqliBooleanPlugin extends MutationFilteredSignaturePlugin {
  readonly name = SignatureId("sqli-boolean");
  protected readonly groups = [SignatureGroupId("sqli")];
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const truePayload = BuiltinPayload.String("' AND 1=1--");
    const trueResult = await replay([
      parameter.createMutation(truePayload, BuiltinMutationType.AppendValue),
    ]);

    const falsePayload = BuiltinPayload.String("' AND 1=2--");
    const falseResult = await replay([
      parameter.createMutation(falsePayload, BuiltinMutationType.AppendValue),
    ]);

    const trueBody = trueResult.exchange.response.body?.toString() ?? "";
    const falseBody = falseResult.exchange.response.body?.toString() ?? "";
    const trueStatus = trueResult.exchange.response.statusCode;
    const falseStatus = falseResult.exchange.response.statusCode;

    const allExchanges: Exchange[] = [
      ...trueResult.allExchanges,
      ...falseResult.allExchanges,
    ];
    const vulnerable =
      trueBody !== falseBody || trueStatus !== falseStatus;
    const evidenceExchanges = vulnerable
      ? [trueResult.exchange, falseResult.exchange]
      : [];

    const evidence: Evidence = {
      judgmentId: "boolean-based-differential",
      exchanges: allExchanges,
      evidenceExchanges,
    };
    return {
      vulnerable,
      evidence,
      request: trueResult.exchange.request,
      response: trueResult.exchange.response,
    };
  }
}
