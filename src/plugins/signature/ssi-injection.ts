import {
  SignatureId,
} from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

interface SsiPayload {
  template: string;
  result: string;
}

const MARKER = "gevanni_";

const SSI_PAYLOADS: SsiPayload[] = [
  { template: `<!--#echo var="DATE_LOCAL" -->`, result: MARKER },
  { template: `<!--#exec cmd="echo ${MARKER}ssi"-->`, result: `${MARKER}ssi` },
];

export class SsiInjectionPlugin extends MutationFilteredSignaturePlugin {
  readonly name = SignatureId("ssi-injection");

  constructor() {
    super([BuiltinMutationType.AppendValue]);
  }

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const allExchanges: Exchange[] = [];
    const matches: Exchange[] = [];

    for (const { template, result } of SSI_PAYLOADS) {
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
      judgmentId: "ssi-directive-execution",
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
