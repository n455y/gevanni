import type { CommandBus } from "./command-bus.ts";
import type { EventBus } from "./event-bus.ts";
import type { Logger } from "./logger.ts";
import type { RuntimeContext } from "./runtime-context.ts";

export interface PluginContext {
  commandBus: CommandBus;
  eventBus: EventBus;
  logger: Logger;
  pluginRegistry?: PluginRegistry;
}

export interface Plugin {
  readonly name: string;
  init(context: PluginContext): Promise<void>;
  destroy?(): Promise<void>;
}

export interface ScenarioPlugin extends Plugin {
  readonly name: `scenario:${string}`;
}

export interface ProxyPlugin extends Plugin {
  readonly name: `proxy:${string}`;
}

export interface ReporterPlugin extends Plugin {
  readonly name: `reporter:${string}`;
}

export interface StoragePlugin extends Plugin {
  readonly name: `storage:${string}`;
}

export interface ParserPlugin extends Plugin {
  readonly name: `parser:${string}`;
}

export interface MutationPlugin extends Plugin {
  readonly name: `mutation:${string}`;
}

export interface SignaturePlugin extends Plugin {
  readonly name: `signature:${string}`;
}

export interface PluginRegistry {
  register(plugin: Plugin): void;
  initializeAll(context: RuntimeContext): Promise<Plugin[]>;
  destroyAll(plugins: Plugin[]): Promise<void>;
  getByName<T extends Plugin = Plugin>(name: string): T | undefined;
}

export class PluginRegistryImpl implements PluginRegistry {
  private plugins = new Map<string, Plugin>();

  register(plugin: Plugin): void {
    this.plugins.set(plugin.name, plugin);
  }

  async initializeAll(context: RuntimeContext): Promise<Plugin[]> {
    for (const plugin of this.plugins.values()) {
      await plugin.init({
        commandBus: context.commandBus,
        eventBus: context.eventBus,
        logger: context.logger,
        pluginRegistry: this,
      });
    }
    return Array.from(this.plugins.values());
  }

  async destroyAll(plugins: Plugin[]): Promise<void> {
    for (const plugin of plugins) {
      if (plugin.destroy) {
        await plugin.destroy();
      }
    }
  }

  getByName<T extends Plugin = Plugin>(name: string): T | undefined {
    return this.plugins.get(name) as T | undefined;
  }
}
