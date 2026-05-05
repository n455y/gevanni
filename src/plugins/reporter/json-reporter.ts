import { promises as fs } from "node:fs";
import { join } from "node:path";
import type { Plugin, PluginContext } from "../../core/plugin.js";
import type { Job, ScanState } from "../../types/models.js";
import { GenerateReportCommand } from "../../commands/report.js";

interface JsonReporterConfig {
  outputPath?: string;
}

interface ReportSummary {
  total: number;
  vulnerable: number;
  safe: number;
  errors: number;
}

interface Report {
  scanState: ScanState;
  jobs: Job[];
  summary: ReportSummary;
}

function computeSummary(jobs: Job[]): ReportSummary {
  let vulnerable = 0;
  let safe = 0;
  let errors = 0;

  for (const job of jobs) {
    if (job.status === ("completed" as Job["status"])) {
      if (job.finding?.vulnerable) {
        vulnerable++;
      } else {
        safe++;
      }
    } else if (job.status === ("error" as Job["status"])) {
      errors++;
    }
  }

  return {
    total: jobs.length,
    vulnerable,
    safe,
    errors,
  };
}

function createJsonReporterPlugin(): Plugin {
  return {
    name: "json-reporter",

    async init(ctx: PluginContext): Promise<void> {
      const cfg = ctx.config as JsonReporterConfig;

      ctx.commandBus.register(GenerateReportCommand, async (cmd) => {
        const { scanState, jobs } = cmd.payload;

        const summary = computeSummary(jobs);

        const report: Report = {
          scanState,
          jobs,
          summary,
        };

        const outputPath =
          cfg.outputPath ??
          `gevanni-report-${scanState.id as string}.json`;

        const dir = join(outputPath, "..");
        await fs.mkdir(dir, { recursive: true });
        await fs.writeFile(
          outputPath,
          JSON.stringify(report, null, 2),
          "utf-8",
        );
      });
    },
  };
}

export { createJsonReporterPlugin };
