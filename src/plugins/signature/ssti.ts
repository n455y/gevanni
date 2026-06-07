import { SignatureGroupId } from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

interface SstiPayload {
  template: string;
  result: string;
}

const MARKER = "gevanni_";

const SSTI_PAYLOADS: SstiPayload[] = [
  { template: `{{${MARKER}7*7}}`, result: `${MARKER}49` },
  { template: `\${${MARKER}7*7}`, result: `${MARKER}49` },
  { template: `<%=${MARKER}7*7%>`, result: `${MARKER}49` },
];

export class SstiPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:ssti";
  protected readonly groups = [SignatureGroupId("ssti")];
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const allExchanges: Exchange[] = [];
    const matches: Exchange[] = [];

    for (const { template, result } of SSTI_PAYLOADS) {
      const payload = BuiltinPayload.String(template);
      const instruction = parameter.createMutation(
        payload,
        BuiltinMutationType.AppendValue,
      );
      const replayResult = await replay([instruction]);
      allExchanges.push(...replayResult.allExchanges);
      matches.push(
        ...replayResult.allExchanges.filter((ex) =>
          (ex.response.body?.toString() ?? "").includes(result),
        ),
      );
      if (matches.length > 0) break;
    }

    const evidence: Evidence = {
      judgmentId: "template-evaluation",
      exchanges: allExchanges,
      evidenceExchanges: matches,
    };
    return {
      vulnerable: matches.length > 0,
      evidence,
      request: allExchanges[0]?.request ?? {
        method: "GET",
        url: "",
        headers: {},
        body: null,
      },
      response: allExchanges[0]?.response ?? {
        statusCode: 0,
        headers: {},
        body: null,
      },
    };
  }
}
