import { BroadcastCommand } from "../core/command.js";
import type { HttpRequest, AuditTarget } from "../types/models.js";

class ParseRequestCommand extends BroadcastCommand<AuditTarget[]> {
  readonly type = "parseRequest";
  constructor(readonly request: HttpRequest) {
    super();
  }
}
export { ParseRequestCommand };
