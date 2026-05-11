import { SingleCommand } from "../core/command.ts";
import type { Exchange } from "../types/models.ts";

export class SaveExchangeCommand extends SingleCommand<void> {
  readonly type = "saveExchange";
  readonly replayId: string;
  readonly exchange: Exchange;
  constructor(replayId: string, exchange: Exchange) { super(); this.replayId = replayId; this.exchange = exchange; }
}

export class LoadExchangesCommand extends SingleCommand<Exchange[]> {
  readonly type = "loadExchanges";
  readonly replayId: string;
  constructor(replayId: string) { super(); this.replayId = replayId; }
}
