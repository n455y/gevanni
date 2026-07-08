import { promises as fs } from "node:fs";
import { join } from "node:path";
import type { ReporterPlugin, PluginContext } from "../../core/plugin.ts";
import type { ScanState, SignatureJob } from "../../types/models.ts";
import { serializeSignatureJob, serializeScanState, type SerializedSignatureJob, type SerializedScanState } from "../../types/models.ts";
import { GenerateReportCommand } from "../../commands/report.ts";

export interface JsonReporterConfig {
  outputPath?: string;
}

interface ReportSummary {
  total: number;
  vulnerable: number;
  safe: number;
  errors: number;
  skipped: number;
}

interface ReadableBody {
  base64: string;
  utf8: string | null;
}

interface Report {
  scanState: SerializedScanState;
  jobs: unknown[];
  summary: ReportSummary;
}

function computeSummary(jobs: SignatureJob[]): ReportSummary {
  let vulnerable = 0;
  let safe = 0;
  let errors = 0;
  let skipped = 0;

  for (const job of jobs) {
    if (job.status === ("completed" as SignatureJob["status"])) {
      if (job.finding?.vulnerable) {
        vulnerable++;
      } else {
        safe++;
      }
    } else if (job.status === ("error" as SignatureJob["status"])) {
      errors++;
    } else if (job.status === ("skipped" as SignatureJob["status"])) {
      skipped++;
    }
  }

  return {
    total: jobs.length,
    vulnerable,
    safe,
    errors,
    skipped,
  };
}

/**
 * When a Node.js Buffer is JSON-serialized it becomes
 * {"type":"Buffer","data":[60,33,...]}.
 * Always represent as both base64 + UTF-8 text.
 */
function normalizeBody(body: unknown): ReadableBody | null {
  if (body === null || body === undefined) return null;
  if (Buffer.isBuffer(body)) {
    const b = body as Buffer;
    return {
      base64: b.toString("base64"),
      utf8: b.toString("utf-8"),
    };
  }
  if (
    typeof body === "object" &&
    (body as Record<string, unknown>).type === "Buffer" &&
    Array.isArray((body as Record<string, unknown>).data)
  ) {
    const b = Buffer.from((body as { data: number[] }).data);
    return {
      base64: b.toString("base64"),
      utf8: b.toString("utf-8"),
    };
  }
  return null;
}

/**
 * Recursively convert body fields in the object tree to readable format.
 */
function normalizeBodies(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(normalizeBodies);
  if (typeof obj === "object") {
    const record = obj as Record<string, unknown>;
    if ("body" in record) {
      record.body = normalizeBody(record.body);
    }
    for (const key of Object.keys(record)) {
      record[key] = normalizeBodies(record[key]);
    }
    return record;
  }
  return obj;
}

export default class JsonReporterPlugin implements ReporterPlugin {
  readonly name = "reporter:json";
  private outputPath: string | undefined;

  constructor(options: JsonReporterConfig = {}) {
    this.outputPath = options.outputPath;
  }

  async generate(
    scanState: ScanState,
    jobs: SignatureJob[],
    options?: string,
  ): Promise<void> {
    const summary = computeSummary(jobs);

    const report: Report = {
      scanState: serializeScanState(scanState),
      jobs: jobs.map((j) => normalizeBodies(serializeSignatureJob(j))),
      summary,
    };

    const resolvedPath =
      options ?? this.outputPath ?? `gevanni-report-${scanState.id as string}.json`;

    const dir = join(resolvedPath, "..");
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(
      resolvedPath,
      JSON.stringify(report, null, 2),
      "utf-8",
    );
  }

  async init(ctx: PluginContext): Promise<void> {
    ctx.commandBus.register(GenerateReportCommand, async (cmd) => {
      const { scanState, jobs } = cmd.payload;
      await this.generate(scanState, jobs);
    });
  }
}
