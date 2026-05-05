import { SingleCommand } from "../core/command.js";
import type { Job, ScanState, Scenario } from "../types/models.js";
import type { JobId, ScanId, ScenarioId } from "../types/branded.js";

class SaveJobCommand extends SingleCommand<void> {
  readonly type = "saveJob";
  constructor(readonly job: Job) { super(); }
}
class LoadJobCommand extends SingleCommand<Job | null> {
  readonly type = "loadJob";
  constructor(readonly id: JobId) { super(); }
}
class LoadJobsByScanIdCommand extends SingleCommand<Job[]> {
  readonly type = "loadJobsByScanId";
  constructor(readonly scanId: ScanId) { super(); }
}
class LoadPendingJobsCommand extends SingleCommand<Job[]> {
  readonly type = "loadPendingJobs";
  constructor(readonly scanId: ScanId) { super(); }
}
class UpdateJobCommand extends SingleCommand<void> {
  readonly type = "updateJob";
  constructor(readonly id: JobId, readonly updates: Partial<Job>) { super(); }
}
class SaveScanStateCommand extends SingleCommand<void> {
  readonly type = "saveScanState";
  constructor(readonly state: ScanState) { super(); }
}
class LoadScanStateCommand extends SingleCommand<ScanState | null> {
  readonly type = "loadScanState";
  constructor(readonly id: ScanId) { super(); }
}
class LoadScenarioCommand extends SingleCommand<Scenario> {
  readonly type = "loadScenario";
  constructor(readonly id: ScenarioId) { super(); }
}

export { SaveJobCommand, LoadJobCommand, LoadJobsByScanIdCommand, LoadPendingJobsCommand, UpdateJobCommand, SaveScanStateCommand, LoadScanStateCommand, LoadScenarioCommand };
