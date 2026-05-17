import { PartitionedBroadcastCommand } from "../core/command.ts";
import type {
  AuditParameter,
  Finding,
  AuditMutation,
  ReplayResult,
} from "../types/models.ts";
import type { SignatureId } from "../types/branded.ts";

export interface RunAuditContext {
  signatureName: SignatureId;
  parameter: AuditParameter;
  replay: (mutations: AuditMutation[]) => Promise<ReplayResult>;
}

export class RunAuditCommand extends PartitionedBroadcastCommand<Finding | null> {
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
