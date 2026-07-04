import { BroadcastCommand } from "../core/command.ts";
import type { HttpRequest, AuditParameter } from "../types/models.ts";

export class ParseRequestCommand extends BroadcastCommand<AuditParameter[]> {
  readonly type = "parseRequest";
  readonly request: HttpRequest;
  readonly scenario?: unknown;
  constructor(request: HttpRequest, scenario?: unknown) {
    super();
    this.request = request;
    this.scenario = scenario;
  }
}
