import { PipelineCommand } from "../core/command.ts";
import type { Exchange } from "../types/models.ts";

export interface DiffPair {
  label: string;
  exchange: Exchange;
}

export interface DiffResult {
  handled: boolean;
  different: boolean;
  evidenceExchanges: Exchange[];
}

export class DiffCommand extends PipelineCommand<DiffResult> {
  override readonly type = "diff";
  readonly pairs: DiffPair[];
  readonly initial: DiffResult = { handled: false, different: false, evidenceExchanges: [] };

  constructor(pairs: DiffPair[]) {
    super();
    this.pairs = pairs;
  }
}
