import {
  SignatureId,
} from "../../types/branded.ts";
import type { Evidence } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

export const XPATH_ERROR_PATTERNS: RegExp[] = [
  /XPath error/i,
  /Invalid expression/i,
  /compile\(\)/i,
  /XPathException/i,
  /javax\.xml\.xpath/i,
  /System\.Xml\.XPath/i,
];

export class XpathInjectionPlugin extends MutationFilteredSignaturePlugin {
  readonly name = SignatureId("xpath-injection");
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const payload = BuiltinPayload.String("' or '1'='1");
    const instruction = parameter.createMutation(
      payload,
      BuiltinMutationType.AppendValue,
    );
    const result = await replay([instruction]);
    const allExchanges = result.allExchanges;
    const matches = allExchanges.filter((ex) =>
      XPATH_ERROR_PATTERNS.some((p) => p.test(ex.response.body?.toString() ?? "")),
    );
    const evidence: Evidence = {
      judgmentId: "xpath-error-pattern",
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
