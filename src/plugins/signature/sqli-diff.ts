import { SignatureGroupId } from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";
import { DiffCommand } from "../../commands/diff.ts";

export class SqliDiffPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:sqli-diff";
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

    const allExchanges: Exchange[] = [
      ...trueResult.allExchanges,
      ...falseResult.allExchanges,
    ];

    const judgment = await this.commandBus.pipe(
      new DiffCommand([
        { label: "true", exchange: trueResult.exchange },
        { label: "false", exchange: falseResult.exchange },
      ]),
    );

    const evidence: Evidence = {
      judgmentId: "diff-based",
      exchanges: allExchanges,
      evidenceExchanges: judgment.evidenceExchanges,
    };
    return {
      vulnerable: judgment.different,
      evidence,
      request: trueResult.exchange.request,
      response: trueResult.exchange.response,
    };
  }
}
