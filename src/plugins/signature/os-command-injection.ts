import { SignatureGroupId } from "../../types/branded.ts";
import type { Evidence } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

const MARKER = "gevanni_cm7j";

export class OsCommandInjectionPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:os-command-injection";
  protected readonly groups = [SignatureGroupId("os-command-injection")];
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const payload = BuiltinPayload.String(`; echo ${MARKER}`);
    const instruction = parameter.createMutation(
      payload,
      BuiltinMutationType.AppendValue,
    );
    const result = await replay([instruction]);
    const allExchanges = result.allExchanges;
    const matches = allExchanges.filter((ex) =>
      (ex.response.body?.toString() ?? "").includes(MARKER) &&
      !(ex.response.headers?.["content-type"]?.includes("application/json")),
    );
    const evidence: Evidence = {
      judgmentId: "command-output-reflection",
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
