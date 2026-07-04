import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { PluginRegistryImpl } from "../core/plugin.ts";
import { loadPlugins } from "./plugin-loader.ts";

describe("loadPlugins", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gevanni-plugin-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function writePluginFile(
    dir: string,
    filename: string,
    content: string,
  ): string {
    const filePath = path.join(dir, filename);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content, "utf-8");
    return filePath;
  }

  it("registers all builtin plugins for :builtin:", async () => {
    const registry = new PluginRegistryImpl();
    await loadPlugins([":builtin:"], registry, "/any/dir");

    // Check specific known builtin plugins exist
    expect(registry.getByName("scenario:openapi")).toBeDefined();
    expect(registry.getByName("scenario-loader:openapi")).toBeDefined();
    expect(registry.getByName("signature:reflected-xss")).toBeDefined();
    expect(registry.getByName("signature:sqli-error")).toBeDefined();
    expect(registry.getByName("proxy:http")).toBeDefined();
    expect(registry.getByName("storage:json")).toBeDefined();
    expect(registry.getByName("reporter:console")).toBeDefined();
  });

  it("loads plugin from file without options", async () => {
    const registry = new PluginRegistryImpl();
    const pluginCode = `
      export default class TestPlugin {
        readonly name = "test:plugin";
        async init() {}
      }
    `;
    writePluginFile(tmpDir, "test-plugin.ts", pluginCode);

    await loadPlugins(["./test-plugin.ts"], registry, tmpDir);
    const plugin = registry.getByName("test:plugin");
    expect(plugin).toBeDefined();
    expect(plugin?.name).toBe("test:plugin");
  });

  it("loads plugin from file with options", async () => {
    const registry = new PluginRegistryImpl();
    const pluginCode = `
      export default class TestPlugin {
        readonly name = "test:plugin";
        private opts: any;
        constructor(options: any) {
          this.opts = options;
        }
        async init() {}
        getOptions() {
          return this.opts;
        }
      }
    `;
    writePluginFile(tmpDir, "test-plugin.ts", pluginCode);

    await loadPlugins(
      [{ file: "./test-plugin.ts", options: { key: "value" } }],
      registry,
      tmpDir,
    );
    const plugin = registry.getByName("test:plugin") as any;
    expect(plugin).toBeDefined();
    expect(plugin.getOptions()).toEqual({ key: "value" });
  });

  it("overrides plugin with same name (last wins)", async () => {
    const registry = new PluginRegistryImpl();
    const pluginCode1 = `
      export default class TestPlugin {
        readonly name = "test:same";
        readonly version = 1;
        async init() {}
      }
    `;
    const pluginCode2 = `
      export default class TestPlugin {
        readonly name = "test:same";
        readonly version = 2;
        async init() {}
      }
    `;
    writePluginFile(tmpDir, "plugin1.ts", pluginCode1);
    writePluginFile(tmpDir, "plugin2.ts", pluginCode2);

    await loadPlugins(
      [":builtin:", "./plugin1.ts", "./plugin2.ts"],
      registry,
      tmpDir,
    );
    const plugin = registry.getByName("test:same") as any;
    expect(plugin?.version).toBe(2);
  });

  it("throws error for missing default export", async () => {
    const registry = new PluginRegistryImpl();
    const pluginCode = `
      export class TestPlugin {
        readonly name = "test:plugin";
        async init() {}
      }
      // No default export!
    `;
    writePluginFile(tmpDir, "no-default.ts", pluginCode);

    await expect(
      loadPlugins(["./no-default.ts"], registry, tmpDir),
    ).rejects.toThrow("has no default export");
  });

  it("throws error for non-class default export", async () => {
    const registry = new PluginRegistryImpl();
    const pluginCode = `
      export default { name: "not-a-class" };
    `;
    writePluginFile(tmpDir, "not-class.ts", pluginCode);

    await expect(
      loadPlugins(["./not-class.ts"], registry, tmpDir),
    ).rejects.toThrow("is not a class");
  });

  it("throws error for plain function default export (not a class)", async () => {
    const registry = new PluginRegistryImpl();
    const pluginCode = `
      export default function NotAClass() {
        return { name: "test:plugin" };
      }
    `;
    writePluginFile(tmpDir, "plain-fn.ts", pluginCode);

    await expect(
      loadPlugins(["./plain-fn.ts"], registry, tmpDir),
    ).rejects.toThrow("is not a class");
  });

  it("throws error for file not found", async () => {
    const registry = new PluginRegistryImpl();
    await expect(
      loadPlugins(["./nonexistent.ts"], registry, tmpDir),
    ).rejects.toThrow("Failed to import plugin file");
  });
});
