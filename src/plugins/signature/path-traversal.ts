import {
  SignatureGroupId,
  SignatureId,
} from "../../types/branded.ts";
import type { Evidence, Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

export const PATH_TRAVERSAL_PATTERNS: RegExp[] = [
  /root:[x*]:0:0:/,
  /\[extensions\]/i,
  /; for 16-bit app support/i,
];

function containsFileContent(body: string): boolean {
  return PATH_TRAVERSAL_PATTERNS.some((p) => p.test(body));
}

export class PathTraversalPlugin extends MutationFilteredSignaturePlugin {
  readonly name = SignatureId("path-traversal");
  protected readonly groups = [SignatureGroupId("path-traversal")];
  protected readonly mutationTypes = [BuiltinMutationType.ReplaceValue] as const;

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const payloads = [
      BuiltinPayload.String("../../etc/passwd"),
      BuiltinPayload.String("..\\..\\windows\\win.ini"),
    ];

    const allExchanges: Exchange[] = [];
    const matches: Exchange[] = [];

    for (const payload of payloads) {
      const instruction = parameter.createMutation(
        payload,
        BuiltinMutationType.ReplaceValue,
      );
      const result = await replay([instruction]);
      allExchanges.push(...result.allExchanges);
      matches.push(
        ...result.allExchanges.filter((ex) =>
          containsFileContent(ex.response.body?.toString() ?? ""),
        ),
      );
      if (matches.length > 0) break;
    }

    const evidence: Evidence = {
      judgmentId: "file-content-disclosure",
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
