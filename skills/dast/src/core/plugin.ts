import type { CommandBus } from "./command-bus.ts";
import type { EventBus } from "./event-bus.ts";
import type { Logger } from "./logger.ts";
import type { RuntimeContext } from "./runtime-context.ts";
import type { HttpResponse, Scenario } from "../types/models.ts";

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
  /**
   * Validate that this scenario's steps execute successfully with real HTTP requests.
   * Optional — plugins that don't implement it cannot be used with validate-scenarios.
   */
  validateScenario?(
    scenario: Scenario,
    options?: ValidateScenarioOptions,
  ): Promise<ScenarioValidationResult>;
}

export interface ScenarioLoaderPlugin extends Plugin {
  readonly name: `scenario-loader:${string}`;
  loadScenarios(source: unknown): Promise<Scenario[]>;
}

export interface ProxyPlugin extends Plugin {
  readonly name: `proxy:${string}`;
}

export interface ReporterPlugin extends Plugin {
  readonly name: `reporter:${string}`;
  generate?(scanState: any, jobs: any[], options?: string): Promise<void>;
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

// --- Validation result types (generic, not specific to any format) ---

/** Result of verifying a single transition between steps (e.g. link resolution) */
export interface ScenarioValidationTransitionResult {
  description: string;
  resolved: boolean;
  resolvedValue?: string;
  error?: string;
}

/** Result of validating a single step (HTTP request + transitions) */
export interface ScenarioValidationStepResult {
  stepId: string;
  description: string;
  method: string;
  url: string;
  statusCode: number;
  success: boolean;
  error?: string;
  transitions: ScenarioValidationTransitionResult[];
}

/** Overall validation result for one scenario */
export interface ScenarioValidationResult {
  scenarioName: string;
  allValid: boolean;
  steps: ScenarioValidationStepResult[];
}

/** Options for scenario validation */
export interface ValidateScenarioOptions {
  upstreamProxyUrl?: string;
}

export interface PluginRegistry {
  register(plugin: Plugin): void;
  initializeAll(context: RuntimeContext): Promise<Plugin[]>;
  destroyAll(plugins: Plugin[]): Promise<void>;
  getByName<T extends Plugin = Plugin>(name: string): T | undefined;
  getAll(): Plugin[];
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

  getAll(): Plugin[] {
    return Array.from(this.plugins.values());
  }
}
