import { SingleCommand } from "../core/command.ts";
import type { SignatureJob, JobStatus, ScanState, Scenario } from "../types/models.ts";
import type { JobId, ScanId, ScenarioId } from "../types/branded.ts";

export class SaveJobCommand extends SingleCommand<void> {
  readonly type = "saveJob";
  readonly job: SignatureJob;
  constructor(job: SignatureJob) { super(); this.job = job; }
}
export class LoadJobCommand extends SingleCommand<SignatureJob | null> {
  readonly type = "loadJob";
  readonly id: JobId;
  constructor(id: JobId) { super(); this.id = id; }
}
export class LoadJobsByStatusCommand extends SingleCommand<SignatureJob[]> {
  readonly type = "loadJobsByStatus";
  readonly scanId: ScanId;
  readonly statusFilter: JobStatus[];
  constructor(scanId: ScanId, statusFilter: JobStatus[] = []) {
    super();
    this.scanId = scanId;
    this.statusFilter = statusFilter;
  }
}
export class UpdateJobCommand extends SingleCommand<void> {
  readonly type = "updateJob";
  readonly id: JobId;
  readonly updates: Partial<SignatureJob>;
  constructor(id: JobId, updates: Partial<SignatureJob>) { super(); this.id = id; this.updates = updates; }
}
export class SaveScanStateCommand extends SingleCommand<void> {
  readonly type = "saveScanState";
  readonly state: ScanState;
  constructor(state: ScanState) { super(); this.state = state; }
}
export class LoadScanStateCommand extends SingleCommand<ScanState | null> {
  readonly type = "loadScanState";
  readonly id: ScanId;
  constructor(id: ScanId) { super(); this.id = id; }
}
export class SaveScenarioCommand extends SingleCommand<void> {
  readonly type = "saveScenario";
  readonly scenario: Scenario;
  constructor(scenario: Scenario) { super(); this.scenario = scenario; }
}
export class LoadScenarioCommand extends SingleCommand<Scenario> {
  readonly type = "loadScenario";
  readonly id: ScenarioId;
  constructor(id: ScenarioId) { super(); this.id = id; }
}
