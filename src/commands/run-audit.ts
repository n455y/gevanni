import { PartitionedSingleCommand } from "../core/command.ts";
import type {
  AuditParameter,
  Finding,
  AuditMutation,
  ReplayResult,
  Job,
} from "../types/models.ts";
import type { ErrorMessage, ScenarioId, SignatureId } from "../types/branded.ts";

export type AuditResult =
  | { status: "completed"; finding: Finding }
  | { status: "skipped" }
  | { status: "error"; error: ErrorMessage };

export interface RunAuditContext {
  signatureName: SignatureId;
  scenarioId: ScenarioId;
  parameter: AuditParameter;
  replay: (mutations: AuditMutation[]) => Promise<ReplayResult>;
  completedJobs: Job[];
}

export class RunAuditCommand extends PartitionedSingleCommand<AuditResult> {
  readonly type = "runAudit";
  readonly context: RunAuditContext;
  get partition() {
    return this.context.signatureName;
  }
  constructor(context: RunAuditContext) {
    super();
    this.context = context;
  }
}
