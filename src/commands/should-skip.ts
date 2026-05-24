import { PartitionedBroadcastCommand } from "../core/command.ts";
import type { Job } from "../types/models.ts";
import type { SignatureId } from "../types/branded.ts";

export interface ShouldSkipContext {
  signatureName: SignatureId;
  completedJobs: Job[];
}

export class ShouldSkipCommand extends PartitionedBroadcastCommand<boolean> {
  readonly type = "shouldSkip";
  readonly context: ShouldSkipContext;
  get partition() {
    return this.context.signatureName;
  }
  constructor(context: ShouldSkipContext) {
    super();
    this.context = context;
  }
}
