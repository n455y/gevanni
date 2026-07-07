import type { ReporterPlugin, PluginContext } from "../../core/plugin.ts";
import type { ScanState, SignatureJob, HttpRequest, HttpResponse } from "../../types/models.ts";
import { GenerateReportCommand } from "../../commands/report.ts";

// ── Security-relevant response headers ────────────────────────────

const SECURITY_HEADERS = [
  "server",
  "x-powered-by",
  "x-aspnet-version",
  "x-generator",
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "strict-transport-security",
  "set-cookie",
  "x-cache",
  "x-debug",
  "x-runtime",
];

// ── Formatting helpers ─────────────────────────────────────────────

function formatParameter(job: SignatureJob): string {
  const p = job.parameter;
  const loc =
    typeof p.location === "object" && p.location !== null
      ? JSON.stringify(p.location)
      : String(p.location);
  const val =
    typeof p.originalValue === "object" && p.originalValue !== null
      ? JSON.stringify(p.originalValue)
      : String(p.originalValue);
  return `${p.constructor.name} ${loc} = ${val}`;
}

function truncate(str: string, maxLen = 300): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + `... [+${str.length - maxLen} chars]`;
}

function formatBody(body: Buffer | null): string {
  if (!body || body.length === 0) return "(empty)";
  return truncate(body.toString("utf-8"));
}

function formatHeadersOfInterest(headers: Record<string, string>): string {
  return SECURITY_HEADERS
    .filter((k) => headers[k] !== undefined)
    .map((k) => `    ${k}: ${headers[k]}`)
    .join("\n");
}

function formatRequestDetails(req: HttpRequest): string[] {
  const lines: string[] = [];
  lines.push(`  Request: ${req.method} ${req.url}`);
  if (req.body && req.body.length > 0) {
    lines.push(`  Request Body: ${formatBody(req.body)}`);
  }
  return lines;
}

function formatResponseDetails(res: HttpResponse): string[] {
  const lines: string[] = [];
  lines.push(`  Response Status: ${res.statusCode}`);
  if (res.body && res.body.length > 0) {
    lines.push(`  Response Body: ${formatBody(res.body)}`);
  }
  const secHeaders = formatHeadersOfInterest(res.headers);
  if (secHeaders.length > 0) {
    lines.push(`  Response Headers:\n${secHeaders}`);
  }
  return lines;
}

// ── Reporter plugin ────────────────────────────────────────────────

export default class ConsoleReporterPlugin implements ReporterPlugin {
  readonly name = "reporter:console";

  async generate(
    scanState: ScanState,
    jobs: SignatureJob[],
    _options?: string,
  ): Promise<void> {
    const lines: string[] = [];

    lines.push("=== Gevanni Scan Report ===");
    lines.push(`Scan ID: ${scanState.id as string}`);
    lines.push(`Status: ${scanState.status as string}`);
    lines.push(`Started: ${scanState.startedAt.toISOString()}`);
    lines.push("");

    let vulnerable = 0;
    let safe = 0;
    let errors = 0;

    // ── Findings ──────────────────────────────────────────────────
    lines.push("--- Findings ---");
    lines.push("");

    for (const job of jobs) {
      if (job.status === ("completed" as SignatureJob["status"])) {
        if (job.finding?.vulnerable) {
          vulnerable++;

          lines.push(`┌─ [VULNERABLE] ${job.signatureName}`);
          lines.push(`│  Group: ${job.groups.join(", ") as string}`);
          lines.push(`│  Target: ${formatParameter(job)}`);

          // Request details (method, URL, body)
          for (const reqLine of formatRequestDetails(job.finding.request)) {
            lines.push(`│  ${reqLine.trimStart()}`);
          }

          // Response details (status, body excerpt, security headers)
          for (const resLine of formatResponseDetails(job.finding.response)) {
            lines.push(`│  ${resLine.trimStart()}`);
          }

          // Evidence exchanges — the proof that confirmed the vulnerability
          const evidenceExchanges = job.finding.evidence.evidenceExchanges;
          lines.push(`│  Judgment: ${job.finding.evidence.judgmentId} (${evidenceExchanges.length} evidence exchange(s))`);

          for (let i = 0; i < evidenceExchanges.length; i++) {
            const ex = evidenceExchanges[i];
            lines.push(`│  Evidence #${i + 1}:`);
            lines.push(`│    ${ex.request.method} ${ex.request.url} → ${ex.response.statusCode}`);
            if (ex.response.body && ex.response.body.length > 0) {
              lines.push(`│    Response: ${formatBody(ex.response.body)}`);
            }
          }

          lines.push("");
        } else {
          safe++;
          lines.push(`[SAFE] ${job.signatureName}`);
          lines.push(`  Target: ${formatParameter(job)}`);
          lines.push("");
        }
      } else if (job.status === ("error" as SignatureJob["status"])) {
        errors++;
        lines.push(`[ERROR] ${job.signatureName}`);
        if (job.error) {
          lines.push(`  Error: ${job.error as string}`);
        }
        lines.push("");
      }
    }

    // ── Summary ────────────────────────────────────────────────────
    lines.push("--- Summary ---");
    lines.push(`Total jobs: ${jobs.length}`);
    lines.push(`Vulnerable: ${vulnerable}`);
    lines.push(`Safe: ${safe}`);
    lines.push(`Errors: ${errors}`);

    console.log(lines.join("\n"));
  }

  async init(ctx: PluginContext): Promise<void> {
    ctx.commandBus.register(GenerateReportCommand, async (cmd) => {
      const { scanState, jobs } = cmd.payload;
      await this.generate(scanState, jobs);
    });
  }
}
