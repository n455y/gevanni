import { SignatureGroupId } from "../../types/branded.ts";
import type { Exchange } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { SignaturePluginBase } from "./base.ts";

export const STACK_TRACE_PATTERNS: RegExp[] = [
  /(?:^|\n)at\s+(?:async\s+)?\S+\s+\(?(?:\/[^\s:)]+):\d+:\d+/,
  /(?:^|\n)\s+at\s+\S+\s+\([^)]+:\d+:\d+\)/,
  /(?:^|\n)Traceback\s+\(most\s+recent\s+call\s+last\)/i,
  /(?:^|\n)\s+File\s+"[^"]+",\s+line\s+\d+/,
  /(?:^|\n)Error:\s+[^\n]*\n\s+at\s+/,
  /(?:^|\n)ENOENT:\s+no\s+such\s+file\s+or\s+directory/i,
  /(?:^|\n)SQLITE_[A-Z_]+:\s+/,
  /(?:^|\n)Sequelize\w*Error:/,
  /(?:^|\n)\w+Error:\s+[^\n]*\/[^\s\n]+\/[^\s\n]+/,
];

export const TECHNOLOGY_LEAK_PATTERNS: RegExp[] = [
  /X-Powered-By:\s*(.+)/i,
  /Server:\s*(.+)/i,
  /X-Generator:\s*(.+)/i,
  /X-AspNet-Version:\s*(.+)/i,
];

/** Default internal path patterns to detect in response bodies. */
export const DEFAULT_INTERNAL_PATH_PATTERNS: string[] = [
  "/var/www/",
  "/home/",
  "/app/",
  "node_modules",
  "/opt/",
  "/etc/",
  "/usr/",
  "WEB-INF",
  ".git/",
  ".env",
];

export interface InfoDisclosurePluginOptions {
  /** Additional path strings to search for in response bodies. Merged with defaults. */
  internalPathPatterns?: string[];
}

export default class InfoDisclosurePlugin extends SignaturePluginBase {
  readonly name = "signature:info-disclosure";
  protected readonly groups = [SignatureGroupId("info-disclosure")];

  private readonly pathPatterns: string[];

  constructor(opts?: InfoDisclosurePluginOptions) {
    super();
    this.pathPatterns = [
      ...DEFAULT_INTERNAL_PATH_PATTERNS,
      ...(opts?.internalPathPatterns ?? []),
    ];
  }

  protected async runAudit({ parameter, replay }: RunAuditContext) {
    const result = await replay([]);
    const response = result.exchange.response;
    const body = response.body?.toString() ?? "";
    const headers = response.headers ?? {};
    const statusCode = response.statusCode;

    const findings: Array<{ type: string; evidence: string }> = [];

    // Check for stack traces and internal paths in response body
    for (const pattern of STACK_TRACE_PATTERNS) {
      const match = body.match(pattern);
      if (match) {
        findings.push({
          type: "stack_trace_or_internal_path",
          evidence: match[0].substring(0, 200),
        });
        break;
      }
    }

    // Check for technology version leaks in headers
    const headerEntries = Object.entries(headers);
    for (const pattern of TECHNOLOGY_LEAK_PATTERNS) {
      const match = headerEntries.some(([key, value]) => {
        const headerLine = `${key}: ${value}`;
        return pattern.test(headerLine);
      });
      if (match) {
        findings.push({
          type: "technology_version_leak",
          evidence: JSON.stringify(headers).substring(0, 200),
        });
        break;
      }
    }

    // Check for internal filesystem paths in response body
    for (const pathPattern of this.pathPatterns) {
      if (body.includes(pathPattern)) {
        findings.push({
          type: "internal_path_disclosure",
          evidence: `Response body contains path: ${pathPattern}`,
        });
        break;
      }
    }

    // Check for detailed error on 500 responses
    if (statusCode >= 500 && body.length > 0 && body.includes("Error")) {
      findings.push({
        type: "detailed_error_response",
        evidence: body.substring(0, 200),
      });
    }

    return {
      vulnerable: findings.length > 0,
      evidence: {
        judgmentId: "info-disclosure-detected",
        exchanges: [result.exchange],
        evidenceExchanges: findings.length > 0 ? [result.exchange] : [],
      },
      request: result.exchange.request,
      response: result.exchange.response,
    };
  }
}
