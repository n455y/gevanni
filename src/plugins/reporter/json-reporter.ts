import { promises as fs } from "node:fs";
import { join } from "node:path";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import { serializeJob, serializeScanState, type Job, type SerializedJob, type SerializedScanState } from "../../types/models.ts";
import { GenerateReportCommand } from "../../commands/report.ts";

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
  scanState: SerializedScanState;
  jobs: SerializedJob[];
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

class JsonReporterPlugin implements Plugin {
  readonly name = "json-reporter";
  private outputPath: string | undefined;

  async init(ctx: PluginContext): Promise<void> {
    const cfg = ctx.config as JsonReporterConfig;
    this.outputPath = cfg.outputPath;

    ctx.commandBus.register(GenerateReportCommand, async (cmd) => {
      const { scanState, jobs } = cmd.payload;

      const summary = computeSummary(jobs);

      const report: Report = {
        scanState: serializeScanState(scanState),
        jobs: jobs.map(serializeJob),
        summary,
      };

      const resolvedPath =
        this.outputPath ??
        `gevanni-report-${scanState.id as string}.json`;

      const dir = join(resolvedPath, "..");
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(
        resolvedPath,
        JSON.stringify(report, null, 2),
        "utf-8",
      );
    });
  }
}

export { JsonReporterPlugin };
