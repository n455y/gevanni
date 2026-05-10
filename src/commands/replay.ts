import { SingleCommand } from "../core/command.js";
import type { Scenario, AuditMutation, Exchange } from "../types/models.js";

interface ReplayConfig {
  instructions: AuditMutation[];
  proxyPort: number;
  replayId: string;
}

class ReplayCommand extends SingleCommand<Exchange[]> {
  readonly type = "replay";
  constructor(readonly scenario: Scenario, readonly config: ReplayConfig) { super(); }
}

export { ReplayCommand, ReplayConfig };
