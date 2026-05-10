import { BroadcastCommand } from "../core/command.ts";
import type { HttpRequest, AuditTarget } from "../types/models.ts";

class ParseRequestCommand extends BroadcastCommand<AuditTarget[]> {
  readonly type = "parseRequest";
  readonly request: HttpRequest;
  constructor(request: HttpRequest) {
    super();
    this.request = request;
  }
}
export { ParseRequestCommand };
