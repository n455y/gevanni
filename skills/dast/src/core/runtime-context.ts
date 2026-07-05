import { InMemoryCommandBus, type CommandBus } from "./command-bus.ts";
import { InMemoryEventBus, type EventBus } from "./event-bus.ts";
import { createLogger, type Logger } from "./logger.ts";
import type { PluginRegistry } from "./plugin.ts";

export class RuntimeContext {
  readonly commandBus: CommandBus;
  readonly eventBus: EventBus;
  readonly logger: Logger;
  pluginRegistry?: PluginRegistry;

  constructor(deps?: {
    commandBus?: CommandBus;
    eventBus?: EventBus;
    logger?: Logger;
    pluginRegistry?: PluginRegistry;
  }) {
    this.commandBus = deps?.commandBus ?? new InMemoryCommandBus();
    this.eventBus = deps?.eventBus ?? new InMemoryEventBus();
    this.logger = deps?.logger ?? createLogger();
    this.pluginRegistry = deps?.pluginRegistry;
  }
}
