import { BroadcastCommand } from "../core/command.js";
import type { HttpRequest, AuditTarget } from "../types/models.js";

class ParseRequestCommand extends BroadcastCommand<AuditTarget[]> {
  readonly type = "parseRequest";
  readonly request: HttpRequest;
  constructor(request: HttpRequest) {
    super();
    this.request = request;
  }
}
export { ParseRequestCommand };
