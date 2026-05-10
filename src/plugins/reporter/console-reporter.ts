import type { Plugin, PluginContext } from "../../core/plugin.ts";
import type { Job } from "../../types/models.ts";
import { GenerateReportCommand } from "../../commands/report.ts";

function formatParameter(job: Job): string {
  const p = job.parameter;
  const loc =
    typeof p.location === "object" && p.location !== null
      ? JSON.stringify(p.location)
      : String(p.location);
  return `${p.constructor.name} ${loc} = ${String(p.originalValue)}`;
}

class ConsoleReporterPlugin implements Plugin {
  readonly name = "console-reporter";

  async init(ctx: PluginContext): Promise<void> {
    ctx.commandBus.register(GenerateReportCommand, async (cmd) => {
      const { scanState, jobs } = cmd.payload;

      const lines: string[] = [];

      lines.push("=== Gevanni Scan Report ===");
      lines.push(`Scan ID: ${scanState.id as string}`);
      lines.push(`Status: ${scanState.status as string}`);
      lines.push(`Started: ${scanState.startedAt.toISOString()}`);
      lines.push("");
      lines.push("--- Findings ---");
      lines.push("");

      let vulnerable = 0;
      let safe = 0;
      let errors = 0;

      for (const job of jobs) {
        if (job.status === ("completed" as Job["status"])) {
          if (job.finding?.vulnerable) {
            vulnerable++;
            lines.push(`[VULNERABLE] ${job.signatureName}`);
            lines.push(`  Target: ${formatParameter(job)}`);
            lines.push(
              `  Evidence: ${job.finding.evidence as string}`,
            );
            lines.push(
              `  Request: ${job.finding.request.method} ${job.finding.request.url}`,
            );
            lines.push("");
          } else {
            safe++;
            lines.push(`[SAFE] ${job.signatureName}`);
            lines.push(`  Target: ${formatParameter(job)}`);
            lines.push("");
          }
        } else if (job.status === ("error" as Job["status"])) {
          errors++;
          lines.push(`[ERROR] ${job.signatureName}`);
          if (job.error) {
            lines.push(`  Error: ${job.error as string}`);
          }
          lines.push("");
        }
      }

      lines.push("--- Summary ---");
      lines.push(`Total jobs: ${jobs.length}`);
      lines.push(`Vulnerable: ${vulnerable}`);
      lines.push(`Safe: ${safe}`);
      lines.push(`Errors: ${errors}`);

      console.log(lines.join("\n"));
    });
  }
}

export { ConsoleReporterPlugin };
