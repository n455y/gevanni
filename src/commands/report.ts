import { BroadcastCommand } from "../core/command.js";
import type { Job, ScanState } from "../types/models.js";

class GenerateReportCommand extends BroadcastCommand<void> {
  readonly type = "generateReport";
  readonly payload: { scanState: ScanState; jobs: Job[] };
  constructor(payload: { scanState: ScanState; jobs: Job[] }) { super(); this.payload = payload; }
}
export { GenerateReportCommand };
