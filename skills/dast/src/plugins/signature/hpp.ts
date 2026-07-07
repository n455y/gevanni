import { SignatureGroupId } from "../../types/branded.ts";
import type { Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

export interface HppPluginOptions {
  /** Minimum body length difference (bytes) to consider response differential significant */
  diffThreshold?: number;
}

export default class HppPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:hpp";
  protected readonly groups = [SignatureGroupId("hpp")];
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  private readonly diffThreshold: number;

  constructor(opts?: HppPluginOptions) {
    super();
    this.diffThreshold = opts?.diffThreshold ?? 50;
  }

  protected async runAudit({
    parameter,
    replay,
    scenario,
  }: RunAuditContext) {
    // Send a normal request first to get baseline
    const normalPayload = BuiltinPayload.String("normal_test_value");
    const normalResult = await replay([
      parameter.createMutation(normalPayload, BuiltinMutationType.AppendValue),
    ]);

    // Now send the same parameter again with a different value (HPP)
    const hppPayload = BuiltinPayload.String("hpp_duplicate_value");
    const hppResult = await replay([
      parameter.createMutation(hppPayload, BuiltinMutationType.AppendValue),
    ]);

    const allExchanges: Exchange[] = [
      ...normalResult.allExchanges,
      ...hppResult.allExchanges,
    ];

    // Check for differential behavior that indicates HPP vulnerability
    const normalBody = normalResult.exchange.response.body?.toString() ?? "";
    const hppBody = hppResult.exchange.response.body?.toString() ?? "";
    const normalStatus = normalResult.exchange.response.statusCode;
    const hppStatus = hppResult.exchange.response.statusCode;

    const isVulnerable =
      // Status changed - indicates the duplicate parameter affected processing
      normalStatus !== hppStatus ||
      // Body content significantly different
      (Math.abs(normalBody.length - hppBody.length) > this.diffThreshold &&
        normalStatus === hppStatus &&
        normalStatus < 500) ||
      // HPP-specific indicators in response
      (hppBody.includes("hpp_duplicate_value") &&
        !normalBody.includes("hpp_duplicate_value"));

    const judgment = this.compareDiff(
      normalResult.exchange,
      hppResult.exchange,
      scenario.diffStrategy,
    );

    return {
      vulnerable: isVulnerable || judgment.hasDifferent,
      evidence: {
        judgmentId: "hpp-differential",
        exchanges: allExchanges,
        evidenceExchanges: [normalResult.exchange, hppResult.exchange],
      },
      request: hppResult.exchange.request,
      response: hppResult.exchange.response,
    };
  }
}
