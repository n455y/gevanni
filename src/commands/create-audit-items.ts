import { BroadcastCommand } from "../core/command.js";
import type { AuditTarget } from "../types/models.js";
import type { AuditItem } from "../core/audit-item.js";

class CreateAuditItemsCommand extends BroadcastCommand<AuditItem[]> {
  readonly type = "createAuditItems";
  readonly targets: AuditTarget[];
  constructor(targets: AuditTarget[]) {
    super();
    this.targets = targets;
  }
}
export { CreateAuditItemsCommand };
