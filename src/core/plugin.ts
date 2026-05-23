import type { CommandBus } from "./command-bus.ts";
import type { EventBus } from "./event-bus.ts";
import type { Logger } from "./logger.ts";
import type { RuntimeContext } from "./runtime-context.ts";

export interface PluginContext {
  commandBus: CommandBus;
  eventBus: EventBus;
  logger: Logger;
}

export interface Plugin {
  readonly name: string;
  init(context: PluginContext): Promise<void>;
  destroy?(): Promise<void>;
}

export interface PluginRegistry {
  register(plugin: Plugin): void;
  initializeAll(context: RuntimeContext): Promise<Plugin[]>;
  destroyAll(plugins: Plugin[]): Promise<void>;
}

export class PluginRegistryImpl implements PluginRegistry {
  private plugins: Plugin[] = [];

  register(plugin: Plugin): void {
    this.plugins.push(plugin);
  }

  async initializeAll(context: RuntimeContext): Promise<Plugin[]> {
    for (const plugin of this.plugins) {
      await plugin.init({
        commandBus: context.commandBus,
        eventBus: context.eventBus,
        logger: context.logger,
      });
    }
    return this.plugins;
  }

  async destroyAll(plugins: Plugin[]): Promise<void> {
    for (const plugin of plugins) {
      if (plugin.destroy) {
        await plugin.destroy();
      }
    }
  }
}
