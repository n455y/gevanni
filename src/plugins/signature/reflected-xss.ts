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
    const exchange = await replay([instruction]);
    const body = exchange.response.body?.toString() ?? "";
    const vulnerable = body.includes(payload);
    const evidence: Evidence = {
      judgmentId: "payload-reflection",
      exchanges: [exchange],
      evidenceExchanges: vulnerable ? [exchange] : [],
    };
    return {
      vulnerable,
      evidence,
      request: exchange.request,
      response: exchange.response,
    };
  }
}
