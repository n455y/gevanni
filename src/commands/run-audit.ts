import { PartitionedSingleCommand } from "../core/command.ts";
import type {
  AuditParameter,
  Finding,
  AuditMutation,
  ReplayResult,
  Scenario,
  SignatureJob,
} from "../types/models.ts";
import type { ErrorMessage } from "../types/branded.ts";

export type AuditResult =
  | { status: "completed"; finding: Finding }
  | { status: "skipped" }
  | { status: "error"; error: ErrorMessage };

export interface RunAuditContext {
  signatureName: `signature:${string}`;
  scenario: Scenario;
  parameter: AuditParameter;
  replay: (mutations: AuditMutation[]) => Promise<ReplayResult>;
  completedJobs: SignatureJob[];
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
