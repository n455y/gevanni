import type { CommandBus } from "./command-bus.ts";
import type { EventBus } from "./event-bus.ts";
import type { Scenario } from "../types/models.ts";

export interface PluginContext {
  commandBus: CommandBus;
  eventBus: EventBus;
  config: Record<string, unknown>;
}

export interface Plugin {
  readonly name: string;
  init(context: PluginContext): Promise<void>;
  destroy?(): Promise<void>;
}

export interface ScenarioLoaderPlugin extends Plugin {
  load(source: unknown): Promise<Scenario[]>;
}

export interface PluginConfig {
  type: string;
  name: string;
  options: Record<string, unknown>;
}

export interface PluginRegistry {
  register(type: string, name: string, factory: () => Plugin): void;
  initializeAll(deps: {
    commandBus: CommandBus;
    eventBus: EventBus;
    pluginConfigs?: PluginConfig[];
  }): Promise<Plugin[]>;
  destroyAll(plugins: Plugin[]): Promise<void>;
}

export class PluginRegistryImpl implements PluginRegistry {
  private factories = new Map<string, () => Plugin>();

  register(type: string, name: string, factory: () => Plugin): void {
    this.factories.set(`${type}:${name}`, factory);
  }

  async initializeAll(deps: {
    commandBus: CommandBus;
    eventBus: EventBus;
    pluginConfigs?: PluginConfig[];
  }): Promise<Plugin[]> {
    const configs = deps.pluginConfigs ?? [];
    const plugins: Plugin[] = [];

    for (const config of configs) {
      const key = `${config.type}:${config.name}`;
      const factory = this.factories.get(key);
      if (!factory) {
        throw new Error(`No plugin factory registered for: ${key}`);
      }
      const plugin = factory();
      await plugin.init({
        commandBus: deps.commandBus,
        eventBus: deps.eventBus,
        config: config.options,
      });
      plugins.push(plugin);
    }

    return plugins;
  }

  async destroyAll(plugins: Plugin[]): Promise<void> {
    for (const plugin of plugins) {
      if (plugin.destroy) {
        await plugin.destroy();
      }
    }
  }
}
