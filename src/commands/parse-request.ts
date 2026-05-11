import { BroadcastCommand } from "../core/command.ts";
import type { HttpRequest, AuditParameter } from "../types/models.ts";

export class ParseRequestCommand extends BroadcastCommand<AuditParameter[]> {
  readonly type = "parseRequest";
  readonly request: HttpRequest;
  constructor(request: HttpRequest) {
    super();
    this.request = request;
  }
}
