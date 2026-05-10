import { BroadcastCommand } from "../core/command.ts";
import type { AuditTarget } from "../types/models.ts";
import type { AuditItem } from "../core/audit-item.ts";

class CreateAuditItemsCommand extends BroadcastCommand<AuditItem[]> {
  readonly type = "createAuditItems";
  readonly targets: AuditTarget[];
  constructor(targets: AuditTarget[]) {
    super();
    this.targets = targets;
  }
}
export { CreateAuditItemsCommand };
