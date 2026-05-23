import {
  SignatureId,
} from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

const MARKER = "gevanni_pp";

export const PROTOTYPE_POLLUTION_PATTERNS: RegExp[] = [
  /Cannot set property.*of undefined/i,
  /Object\.prototype.*hasOwnProperty/i,
  /TypeError:.*is not a function/i,
  /JSON\.parse.*unexpected/i,
  /Maximum call stack size exceeded/i,
  /RangeError: Maximum call stack/i,
];

export class PrototypePollutionPlugin extends MutationFilteredSignaturePlugin {
  readonly name = SignatureId("prototype-pollution");

  constructor() {
    super([BuiltinMutationType.AppendValue]);
  }

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const payloads = [
      BuiltinPayload.String(`__proto__[${MARKER}]=1`),
      BuiltinPayload.String(`constructor[prototype][${MARKER}]=1`),
    ];

    const allExchanges: Exchange[] = [];
    const matches: Exchange[] = [];

    for (const payload of payloads) {
      const instruction = parameter.createMutation(
        payload,
        BuiltinMutationType.AppendValue,
      );
      const result = await replay([instruction]);
      allExchanges.push(...result.allExchanges);
      matches.push(
        ...result.allExchanges.filter((ex) =>
          PROTOTYPE_POLLUTION_PATTERNS.some((p) => p.test(ex.response.body?.toString() ?? "")),
        ),
      );
      if (matches.length > 0) break;
    }

    const evidence: Evidence = {
      judgmentId: "prototype-pollution-pattern",
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
