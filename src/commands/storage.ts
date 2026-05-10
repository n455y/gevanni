import { SingleCommand } from "../core/command.js";
import type { Job, ScanState, Scenario } from "../types/models.js";
import type { JobId, ScanId, ScenarioId } from "../types/branded.js";

class SaveJobCommand extends SingleCommand<void> {
  readonly type = "saveJob";
  readonly job: Job;
  constructor(job: Job) { super(); this.job = job; }
}
class LoadJobCommand extends SingleCommand<Job | null> {
  readonly type = "loadJob";
  readonly id: JobId;
  constructor(id: JobId) { super(); this.id = id; }
}
class LoadJobsByScanIdCommand extends SingleCommand<Job[]> {
  readonly type = "loadJobsByScanId";
  readonly scanId: ScanId;
  constructor(scanId: ScanId) { super(); this.scanId = scanId; }
}
class LoadPendingJobsCommand extends SingleCommand<Job[]> {
  readonly type = "loadPendingJobs";
  readonly scanId: ScanId;
  constructor(scanId: ScanId) { super(); this.scanId = scanId; }
}
class UpdateJobCommand extends SingleCommand<void> {
  readonly type = "updateJob";
  readonly id: JobId;
  readonly updates: Partial<Job>;
  constructor(id: JobId, updates: Partial<Job>) { super(); this.id = id; this.updates = updates; }
}
class SaveScanStateCommand extends SingleCommand<void> {
  readonly type = "saveScanState";
  readonly state: ScanState;
  constructor(state: ScanState) { super(); this.state = state; }
}
class LoadScanStateCommand extends SingleCommand<ScanState | null> {
  readonly type = "loadScanState";
  readonly id: ScanId;
  constructor(id: ScanId) { super(); this.id = id; }
}
class SaveScenarioCommand extends SingleCommand<void> {
  readonly type = "saveScenario";
  readonly scenario: Scenario;
  constructor(scenario: Scenario) { super(); this.scenario = scenario; }
}
class LoadScenarioCommand extends SingleCommand<Scenario> {
  readonly type = "loadScenario";
  readonly id: ScenarioId;
  constructor(id: ScenarioId) { super(); this.id = id; }
}

export { SaveJobCommand, LoadJobCommand, LoadJobsByScanIdCommand, LoadPendingJobsCommand, UpdateJobCommand, SaveScanStateCommand, LoadScanStateCommand, SaveScenarioCommand, LoadScenarioCommand };
