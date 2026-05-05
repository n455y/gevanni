import { SingleCommand } from "../core/command.js";
import type { Exchange } from "../types/models.js";

class SaveExchangeCommand extends SingleCommand<void> {
  readonly type = "saveExchange";
  constructor(readonly replayId: string, readonly exchange: Exchange) { super(); }
}

class LoadExchangesCommand extends SingleCommand<Exchange[]> {
  readonly type = "loadExchanges";
  constructor(readonly replayId: string) { super(); }
}

export { SaveExchangeCommand, LoadExchangesCommand };
