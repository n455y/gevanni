import { SingleCommand } from "../core/command.ts";
import type { Scenario, AuditMutation, Exchange } from "../types/models.ts";

interface ReplayConfig {
  mutations: AuditMutation[];
  proxyPort: number;
  replayId: string;
}

class ReplayCommand extends SingleCommand<Exchange[]> {
  readonly type = "replay";
  readonly scenario: Scenario;
  readonly config: ReplayConfig;
  constructor(scenario: Scenario, config: ReplayConfig) { super(); this.scenario = scenario; this.config = config; }
}

export { ReplayCommand, type ReplayConfig };
