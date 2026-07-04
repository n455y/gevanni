import { SignatureGroupId } from "../../types/branded.ts";
import type { Evidence } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

export const LDAP_ERROR_PATTERNS: RegExp[] = [
  /ldap_search/i,
  /LDAP error/i,
  /Invalid DN/i,
  /No such object/i,
  /Protocol error.*LDAP/i,
];

export default class LdapInjectionPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:ldap-injection";
  protected readonly groups = [SignatureGroupId("ldap-injection")];
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const payload = BuiltinPayload.String("*)(|(cn=*))");
    const instruction = parameter.createMutation(
      payload,
      BuiltinMutationType.AppendValue,
    );
    const result = await replay([instruction]);
    const allExchanges = result.allExchanges;
    const matches = allExchanges.filter((ex) =>
      LDAP_ERROR_PATTERNS.some((p) =>
        p.test(ex.response.body?.toString() ?? ""),
      ),
    );
    const evidence: Evidence = {
      judgmentId: "ldap-error-pattern",
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
