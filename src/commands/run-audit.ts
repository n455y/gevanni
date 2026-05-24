import { PartitionedSingleCommand } from "../core/command.ts";
import type {
  AuditParameter,
  Finding,
  AuditMutation,
  ReplayResult,
  Job,
} from "../types/models.ts";
import type { SignatureId } from "../types/branded.ts";

export const SKIP_AUDIT = Symbol("skip");

export interface RunAuditContext {
  signatureName: SignatureId;
  parameter: AuditParameter;
  replay: (mutations: AuditMutation[]) => Promise<ReplayResult>;
  completedJobs?: Job[];
}

export class RunAuditCommand extends PartitionedSingleCommand<
  Finding | typeof SKIP_AUDIT
> {
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
