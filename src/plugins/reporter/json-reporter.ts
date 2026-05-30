import { promises as fs } from "node:fs";
import { join } from "node:path";
import type { ReporterPlugin, PluginContext } from "../../core/plugin.ts";
import { serializeSignatureJob, serializeScanState, type SignatureJob, type SerializedSignatureJob, type SerializedScanState } from "../../types/models.ts";
import { GenerateReportCommand } from "../../commands/report.ts";

export interface JsonReporterConfig {
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
  jobs: SerializedSignatureJob[];
  summary: ReportSummary;
}

function computeSummary(jobs: SignatureJob[]): ReportSummary {
  let vulnerable = 0;
  let safe = 0;
  let errors = 0;

  for (const job of jobs) {
    if (job.status === ("completed" as SignatureJob["status"])) {
      if (job.finding?.vulnerable) {
        vulnerable++;
      } else {
        safe++;
      }
    } else if (job.status === ("error" as SignatureJob["status"])) {
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

export class JsonReporterPlugin implements ReporterPlugin {
  readonly name = "reporter:json";
  private outputPath: string | undefined;

  constructor(options: JsonReporterConfig = {}) {
    this.outputPath = options.outputPath;
  }

  async init(ctx: PluginContext): Promise<void> {

    ctx.commandBus.register(GenerateReportCommand, async (cmd) => {
      const { scanState, jobs } = cmd.payload;

      const summary = computeSummary(jobs);

      const report: Report = {
        scanState: serializeScanState(scanState),
        jobs: jobs.map(serializeSignatureJob),
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
