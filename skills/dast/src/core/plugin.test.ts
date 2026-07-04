import { describe, it, expect, vi } from "vitest";
import { InMemoryCommandBus } from "./command-bus.ts";
import { InMemoryEventBus } from "./event-bus.ts";
import {
  PluginRegistryImpl,
  type Plugin,
  type PluginContext,
  type PluginRegistry,
} from "./plugin.ts";
import { RuntimeContext } from "./runtime-context.ts";
import { SingleCommand } from "./command.ts";

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
    const ctx = new RuntimeContext();
    const registry = new PluginRegistryImpl();
    const initSpy = vi.fn();

    registry.register({
      name: "json-parser",
      async init(ctx: PluginContext) {
        initSpy(ctx);
        ctx.commandBus.register(GreetCommand, async (cmd) =>
          `Hello, ${cmd.name}!`,
        );
      },
    });

    const plugins = await registry.initializeAll(ctx);

    expect(plugins).toHaveLength(1);
    expect(plugins[0].name).toBe("json-parser");
    expect(initSpy).toHaveBeenCalledTimes(1);

    // Verify command handler works
    const result = await ctx.commandBus.dispatch(new GreetCommand("world"));
    expect(result).toBe("Hello, world!");
  });

  it("initializes multiple plugins", async () => {
    const ctx = new RuntimeContext();
    const registry = new PluginRegistryImpl();
    const spy1 = vi.fn();
    const spy2 = vi.fn();

    registry.register(createTestPlugin("json-parser", spy1));
    registry.register(createTestPlugin("yaml-parser", spy2));

    const plugins = await registry.initializeAll(ctx);

    expect(plugins).toHaveLength(2);
    expect(plugins[0].name).toBe("json-parser");
    expect(plugins[1].name).toBe("yaml-parser");
    expect(spy1).toHaveBeenCalledTimes(1);
    expect(spy2).toHaveBeenCalledTimes(1);
  });

  it("calls destroy on plugins that have it", async () => {
    const ctx = new RuntimeContext();
    const registry = new PluginRegistryImpl();
    const destroySpy = vi.fn();

    registry.register({
      name: "json-parser",
      async init() {},
      async destroy() {
        destroySpy();
      },
    });

    const plugins = await registry.initializeAll(ctx);

    await registry.destroyAll(plugins);

    expect(destroySpy).toHaveBeenCalledTimes(1);
  });

  it("accepts custom commandBus and eventBus via RuntimeContext", async () => {
    const commandBus = new InMemoryCommandBus();
    const eventBus = new InMemoryEventBus();
    const ctx = new RuntimeContext({ commandBus, eventBus });
    const registry = new PluginRegistryImpl();

    registry.register({
      name: "json-parser",
      async init(ctx: PluginContext) {
        ctx.commandBus.register(GreetCommand, async (cmd) => `Hi, ${cmd.name}!`);
      },
    });

    await registry.initializeAll(ctx);

    // Verify the injected commandBus is used
    const result = await commandBus.dispatch(new GreetCommand("world"));
    expect(result).toBe("Hi, world!");
  });

  it("looks up plugins by name via getByName", () => {
    const registry = new PluginRegistryImpl();
    const plugin = createTestPlugin("json-parser");
    registry.register(plugin);

    expect(registry.getByName("json-parser")).toBe(plugin);
    expect(registry.getByName("missing")).toBeUndefined();
  });

  it("overwrites earlier plugin when same name is registered", () => {
    const registry = new PluginRegistryImpl();
    const first = createTestPlugin("json-parser");
    const second = createTestPlugin("json-parser");
    registry.register(first);
    registry.register(second);

    expect(registry.getByName("json-parser")).toBe(second);
  });

  it("exposes the registry to plugins via PluginContext", async () => {
    const ctx = new RuntimeContext();
    const registry = new PluginRegistryImpl();
    let seen: PluginRegistry | undefined;
    registry.register({
      name: "json-parser",
      async init(ctx: PluginContext) {
        seen = ctx.pluginRegistry;
      },
    });

    await registry.initializeAll(ctx);

    expect(seen).toBe(registry);
  });
});
