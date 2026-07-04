import { SingleCommand } from "../core/command.ts";
import {
  type Scenario,
  type AuditMutation,
  ReplayResult,
} from "../types/models.ts";
import type { ReplayId } from "../types/branded.ts";

export interface ReplayConfig {
  mutations: AuditMutation[];
  proxyPort: number;
  replayId: ReplayId;
}

export class ReplayCommand extends SingleCommand<ReplayResult> {
  readonly type = "replay";
  readonly scenario: Scenario;
  readonly config: ReplayConfig;
  constructor(scenario: Scenario, config: ReplayConfig) { super(); this.scenario = scenario; this.config = config; }
}
