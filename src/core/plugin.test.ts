import { describe, it, expect, vi } from "vitest";
import { SingleCommand } from "./command.ts";
import { InMemoryCommandBus } from "./command-bus.ts";
import { InMemoryEventBus } from "./event-bus.ts";
import { PluginRegistryImpl, type Plugin, type PluginContext } from "./plugin.ts";

// Helper command for testing plugin command handler registration
class GreetCommand extends SingleCommand<string> {
  readonly type = "greet";
  constructor(readonly name: string) {
    super();
  }
}

function createTestPlugin(name: string, onInit?: (ctx: PluginContext) => void): Plugin {
  return {
    name,
    async init(ctx: PluginContext) {
      onInit?.(ctx);
    },
  };
}

describe("PluginRegistryImpl", () => {
  it("registers and initializes plugins", async () => {
    const registry = new PluginRegistryImpl();
    const commandBus = new InMemoryCommandBus();
    const eventBus = new InMemoryEventBus();
    const initSpy = vi.fn();

    registry.register("parser", "json", () => ({
      name: "json-parser",
      async init(ctx: PluginContext) {
        initSpy(ctx);
        ctx.commandBus.register(GreetCommand, async (cmd) =>
          `Hello, ${cmd.name}!`,
        );
      },
    }));

    const plugins = await registry.initializeAll({
      commandBus,
      eventBus,
      pluginConfigs: [{ type: "parser", name: "json", options: {} }],
    });

    expect(plugins).toHaveLength(1);
    expect(plugins[0].name).toBe("json-parser");
    expect(initSpy).toHaveBeenCalledTimes(1);

    // Verify command handler works
    const result = await commandBus.dispatch(new GreetCommand("world"));
    expect(result).toBe("Hello, world!");
  });

  it("initializes multiple plugins", async () => {
    const registry = new PluginRegistryImpl();
    const commandBus = new InMemoryCommandBus();
    const eventBus = new InMemoryEventBus();
    const spy1 = vi.fn();
    const spy2 = vi.fn();

    registry.register("parser", "json", () => createTestPlugin("json-parser", spy1));
    registry.register("parser", "yaml", () => createTestPlugin("yaml-parser", spy2));

    const plugins = await registry.initializeAll({
      commandBus,
      eventBus,
      pluginConfigs: [
        { type: "parser", name: "json", options: {} },
        { type: "parser", name: "yaml", options: {} },
      ],
    });

    expect(plugins).toHaveLength(2);
    expect(plugins[0].name).toBe("json-parser");
    expect(plugins[1].name).toBe("yaml-parser");
    expect(spy1).toHaveBeenCalledTimes(1);
    expect(spy2).toHaveBeenCalledTimes(1);
  });

  it("passes config to plugin", async () => {
    const registry = new PluginRegistryImpl();
    const commandBus = new InMemoryCommandBus();
    const eventBus = new InMemoryEventBus();
    let receivedConfig: Record<string, unknown> | undefined;

    registry.register("storage", "redis", () => ({
      name: "redis-storage",
      async init(ctx: PluginContext) {
        receivedConfig = ctx.config;
      },
    }));

    await registry.initializeAll({
      commandBus,
      eventBus,
      pluginConfigs: [
        {
          type: "storage",
          name: "redis",
          options: { host: "localhost", port: 6379 },
        },
      ],
    });

    expect(receivedConfig).toEqual({ host: "localhost", port: 6379 });
  });

  it("calls destroy on plugins that have it", async () => {
    const registry = new PluginRegistryImpl();
    const commandBus = new InMemoryCommandBus();
    const eventBus = new InMemoryEventBus();
    const destroySpy = vi.fn();

    registry.register("parser", "json", () => ({
      name: "json-parser",
      async init() {},
      async destroy() {
        destroySpy();
      },
    }));

    const plugins = await registry.initializeAll({
      commandBus,
      eventBus,
      pluginConfigs: [{ type: "parser", name: "json", options: {} }],
    });

    await registry.destroyAll(plugins);

    expect(destroySpy).toHaveBeenCalledTimes(1);
  });

  it("throws if plugin not found", async () => {
    const registry = new PluginRegistryImpl();
    const commandBus = new InMemoryCommandBus();
    const eventBus = new InMemoryEventBus();

    // Register one plugin
    registry.register("parser", "json", () => createTestPlugin("json-parser"));

    // But try to initialize a different plugin
    await expect(
      registry.initializeAll({
        commandBus,
        eventBus,
        pluginConfigs: [{ type: "storage", name: "redis", options: {} }],
      }),
    ).rejects.toThrow("No plugin factory registered for: storage:redis");
  });
});
