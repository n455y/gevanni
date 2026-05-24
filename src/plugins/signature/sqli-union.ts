import {
  SignatureId,
  SignatureGroupId,
} from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

const MARKER = "gevanni_union_";

function buildUnionPayloads(columns: number): string[] {
  const payloads: string[] = [];
  for (let n = 1; n <= columns; n++) {
    const cols = Array.from({ length: n }, (_, i) =>
      i === 0 ? `'${MARKER}'` : "NULL",
    );
    payloads.push(`' UNION SELECT ${cols.join(",")}--`);
  }
  return payloads;
}

export const UNION_PAYLOADS = buildUnionPayloads(10);

export class SqliUnionPlugin extends MutationFilteredSignaturePlugin {
  readonly name = SignatureId("sqli-union");
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  protected override get defaultGroups() {
    return [SignatureGroupId("sqli")];
  }

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const allExchanges: Exchange[] = [];
    const matches: Exchange[] = [];

    for (const payloadStr of UNION_PAYLOADS) {
      const payload = BuiltinPayload.String(payloadStr);
      const instruction = parameter.createMutation(
        payload,
        BuiltinMutationType.AppendValue,
      );
      const result = await replay([instruction]);
      allExchanges.push(...result.allExchanges);

      const found = result.allExchanges.filter((ex) =>
        (ex.response.body?.toString() ?? "").includes(MARKER),
      );
      matches.push(...found);
      if (found.length > 0) break;
    }

    const evidence: Evidence = {
      judgmentId: "union-based-marker",
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
