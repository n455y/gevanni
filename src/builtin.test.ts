import { describe, it, expect } from "vitest";
import { PluginRegistryImpl, type ScenarioLoaderPlugin } from "./core/plugin.ts";
import { RuntimeContext } from "./core/runtime-context.ts";
import { registerAllBuiltinPlugins } from "./builtin.ts";

describe("registerAllBuiltinPlugins", () => {
  it("registers scenario-loader:openapi", async () => {
    const registry = new PluginRegistryImpl();
    const ctx = new RuntimeContext();
    registerAllBuiltinPlugins(registry);
    await registry.initializeAll(ctx);

    const loader = registry.getByName<ScenarioLoaderPlugin>("scenario-loader:openapi");
    expect(loader).toBeDefined();
    expect(typeof loader!.loadScenarios).toBe("function");
  });

  it("still registers scenario:openapi (execution side)", async () => {
    const registry = new PluginRegistryImpl();
    const ctx = new RuntimeContext();
    registerAllBuiltinPlugins(registry);
    await registry.initializeAll(ctx);

    expect(registry.getByName("scenario:openapi")).toBeDefined();
  });
});
