import { BroadcastCommand } from "../core/command.js";
import type { Job, ScanState } from "../types/models.js";

class GenerateReportCommand extends BroadcastCommand<void> {
  readonly type = "generateReport";
  constructor(readonly payload: { scanState: ScanState; jobs: Job[] }) { super(); }
}
export { GenerateReportCommand };
