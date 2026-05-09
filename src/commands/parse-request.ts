import { BroadcastCommand } from "../core/command.js";
import type { HttpRequest, InspectionParameter } from "../types/models.js";

class ParseRequestCommand extends BroadcastCommand<InspectionParameter[]> {
  readonly type = "parseRequest";
  constructor(readonly request: HttpRequest) {
    super();
  }
}
export { ParseRequestCommand };
