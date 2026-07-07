import { SignatureGroupId } from "../../types/branded.ts";
import type { Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "./mutation-filtered.ts";

/** Generic SSRF target URLs — override via constructor options for app-specific internal services. */
export const DEFAULT_SSRF_TARGETS: string[] = [
  // AWS metadata endpoint
  "http://169.254.169.254/latest/meta-data/",
  // GCP metadata endpoint
  "http://metadata.google.internal/computeMetadata/v1/",
  // Common localhost ports
  "http://localhost:80/",
  "http://localhost:8080/",
  "http://localhost:3000/",
  "http://127.0.0.1:80/",
  "http://127.0.0.1:8080/",
  "http://127.0.0.1:3000/",
  "http://[::1]:80/",
  "http://[::1]:8080/",
  // File read attempts
  "file:///etc/passwd",
  "file:///etc/hostname",
  // Windows metadata
  "file:///C:/Windows/win.ini",
];

export interface SsrfPluginOptions {
  targetPatterns?: string[];
}

export default class SsrfPlugin extends MutationFilteredSignaturePlugin {
  readonly name = "signature:ssrf";
  protected readonly groups = [SignatureGroupId("ssrf")];
  protected readonly mutationTypes = [BuiltinMutationType.ReplaceValue] as const;

  private readonly targets: string[];

  constructor(opts?: SsrfPluginOptions) {
    super();
    this.targets = opts?.targetPatterns ?? DEFAULT_SSRF_TARGETS;
  }

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const results: Exchange[] = [];

    for (const target of this.targets) {
      const payload = BuiltinPayload.String(target);
      const result = await replay([
        parameter.createMutation(payload, BuiltinMutationType.ReplaceValue),
      ]);

      const body = result.exchange.response.body?.toString() ?? "";
      const statusCode = result.exchange.response.statusCode;

      // SSRF indicators in response
      const isVulnerable =
        // AWS metadata endpoint: response contains instance data
        body.includes("ami-id") ||
        body.includes("instance-id") ||
        body.includes("security-groups") ||
        // GCP metadata
        body.includes("computeMetadata") ||
        // File read success (200 with content)
        (statusCode === 200 && target.startsWith("file://") && body.length > 0);

      results.push(result.exchange);

      if (isVulnerable) {
        return {
          vulnerable: true,
          evidence: {
            judgmentId: "ssrf-request-to-internal",
            exchanges: [result.exchange],
            evidenceExchanges: [result.exchange],
          },
          request: result.exchange.request,
          response: result.exchange.response,
        };
      }
    }

    return {
      vulnerable: false,
      evidence: {
        judgmentId: "ssrf-no-leak",
        exchanges: results,
        evidenceExchanges: [],
      },
      request: results[0]?.request,
      response: results[0]?.response,
    };
  }
}
