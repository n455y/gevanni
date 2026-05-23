import {
  SignatureId,
} from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

const DELAY_SECONDS = 5;
const TIME_THRESHOLD_MS = 4000;

const TIME_PAYLOADS = [
  `'; WAITFOR DELAY '0:0:${DELAY_SECONDS}'--`,
  `' AND SLEEP(${DELAY_SECONDS})--`,
  `' AND pg_sleep(${DELAY_SECONDS})--`,
  `' OR dbms_pipe.receive_message('a',${DELAY_SECONDS})--`,
];

export class SqliTimePlugin extends MutationFilteredSignaturePlugin {
  readonly name = SignatureId("sqli-time");

  constructor() {
    super([BuiltinMutationType.AppendValue]);
  }

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const allExchanges: Exchange[] = [];
    const matches: Exchange[] = [];

    for (const payloadStr of TIME_PAYLOADS) {
      const payload = BuiltinPayload.String(payloadStr);
      const instruction = parameter.createMutation(
        payload,
        BuiltinMutationType.AppendValue,
      );

      const start = Date.now();
      const result = await replay([instruction]);
      const elapsed = Date.now() - start;

      allExchanges.push(...result.allExchanges);

      if (elapsed >= TIME_THRESHOLD_MS) {
        matches.push(...result.allExchanges);
        break;
      }
    }

    const evidence: Evidence = {
      judgmentId: "time-based-delay",
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
