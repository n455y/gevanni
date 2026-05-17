import {
  BuiltinMutationType,
  BuiltinPayload,
  SignatureId,
} from "../../types/branded.ts";
import type { Evidence } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

export class ReflectedXssPlugin extends MutationFilteredSignaturePlugin {
  readonly name = SignatureId("reflected-xss");

  constructor() {
    super([BuiltinMutationType.AppendValue]);
  }

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const payload = BuiltinPayload.String("<script>alert(1)</script>");
    const instruction = parameter.createMutation(
      payload,
      BuiltinMutationType.AppendValue,
    );
    const result = await replay([instruction]);
    const allExchanges = result.allExchanges;
    const reflected = allExchanges.filter(
      (ex) => (ex.response.body?.toString() ?? "").includes(payload),
    );
    const evidence: Evidence = {
      judgmentId: "payload-reflection",
      exchanges: allExchanges,
      evidenceExchanges: reflected,
    };
    return {
      vulnerable: reflected.length > 0,
      evidence,
      request: result.exchange.request,
      response: result.exchange.response,
    };
  }
}
