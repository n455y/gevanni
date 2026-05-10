import { BroadcastCommand } from "../core/command.ts";
import type { Job, ScanState } from "../types/models.ts";

class GenerateReportCommand extends BroadcastCommand<void> {
  readonly type = "generateReport";
  readonly payload: { scanState: ScanState; jobs: Job[] };
  constructor(payload: { scanState: ScanState; jobs: Job[] }) { super(); this.payload = payload; }
}
export { GenerateReportCommand };
