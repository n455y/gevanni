import { SingleCommand } from "../core/command.js";
import type { Scenario, TamperInstruction, HttpRequest, HttpResponse } from "../types/models.js";

interface ReplayConfig {
  instructions: TamperInstruction[];
  proxyPort: number;
}

class ReplayCommand extends SingleCommand<{ request: HttpRequest; response: HttpResponse }> {
  readonly type = "replay";
  constructor(readonly scenario: Scenario, readonly config: ReplayConfig) { super(); }
}

export { ReplayCommand, ReplayConfig };
