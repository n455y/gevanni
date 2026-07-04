import { BroadcastCommand } from "../core/command.ts";
import type { SignatureJob, ScanState } from "../types/models.ts";

export class GenerateReportCommand extends BroadcastCommand<void> {
  readonly type = "generateReport";
  readonly payload: { scanState: ScanState; jobs: SignatureJob[] };
  constructor(payload: { scanState: ScanState; jobs: SignatureJob[] }) { super(); this.payload = payload; }
}
