import { SingleCommand } from "../core/command.js";
import type { Scenario, TamperInstruction, HttpRequest, HttpResponse } from "../types/models.js";

class ReplayCommand extends SingleCommand<{ request: HttpRequest; response: HttpResponse }> {
  readonly type = "replay";
  constructor(readonly scenario: Scenario, readonly instructions: TamperInstruction[]) { super(); }
}
export { ReplayCommand };
