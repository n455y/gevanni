import { SingleCommand } from "../core/command.ts";
import type { Exchange } from "../types/models.ts";
import type { ReplayId } from "../types/branded.ts";

export class SaveExchangeCommand extends SingleCommand<void> {
  readonly type = "saveExchange";
  readonly replayId: ReplayId;
  readonly exchange: Exchange;
  constructor(replayId: ReplayId, exchange: Exchange) { super(); this.replayId = replayId; this.exchange = exchange; }
}

export class LoadExchangesCommand extends SingleCommand<Exchange[]> {
  readonly type = "loadExchanges";
  readonly replayId: ReplayId;
  constructor(replayId: ReplayId) { super(); this.replayId = replayId; }
}
