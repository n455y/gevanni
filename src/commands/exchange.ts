import { SingleCommand } from "../core/command.js";
import type { Exchange } from "../types/models.js";

class SaveExchangeCommand extends SingleCommand<void> {
  readonly type = "saveExchange";
  readonly replayId: string;
  readonly exchange: Exchange;
  constructor(replayId: string, exchange: Exchange) { super(); this.replayId = replayId; this.exchange = exchange; }
}

class LoadExchangesCommand extends SingleCommand<Exchange[]> {
  readonly type = "loadExchanges";
  readonly replayId: string;
  constructor(replayId: string) { super(); this.replayId = replayId; }
}

export { SaveExchangeCommand, LoadExchangesCommand };
