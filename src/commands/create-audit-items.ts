import { BroadcastCommand } from "../core/command.ts";
import type { AuditParameter } from "../types/models.ts";
import type { AuditItem } from "../core/audit-item.ts";

class CreateAuditItemsCommand extends BroadcastCommand<AuditItem[]> {
  readonly type = "createAuditItems";
  readonly parameters: AuditParameter[];
  constructor(parameters: AuditParameter[]) {
    super();
    this.parameters = parameters;
  }
}
export { CreateAuditItemsCommand };
