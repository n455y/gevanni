import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseScenarioSpec, loadScenariosFromSpecs } from "./scenario-spec.ts";
import type { Plugin, PluginRegistry, ScenarioLoaderPlugin } from "../core/plugin.ts";
import { loadOpenApiScenarios } from "../plugins/scenario/openapi/loader.ts";

// Minimal mock helper for the registry
function makeRegistry(loader?: ScenarioLoaderPlugin): Pick<PluginRegistry, "getByName"> {
  return {
    getByName: <T extends Plugin = Plugin>(name: string) =>
      (loader && name === loader.name ? loader : undefined) as T | undefined,
  };
}

describe("parseScenarioSpec", () => {
  it("splits name:path on the first colon", () => {
    expect(parseScenarioSpec("openapi:./spec.yaml")).toEqual({
      loaderName: "openapi",
      path: "./spec.yaml",
    });
  });

  it("preserves additional colons in the path", () => {
    expect(parseScenarioSpec("openapi:http://host/x")).toEqual({
      loaderName: "openapi",
      path: "http://host/x",
    });
  });

  it("throws when the colon is missing", () => {
    expect(() => parseScenarioSpec("./spec.yaml")).toThrow(/Invalid scenario spec/);
  });

  it("throws when the loader name is empty", () => {
    expect(() => parseScenarioSpec(":./spec.yaml")).toThrow(/Invalid scenario spec/);
  });
});

describe("loadScenariosFromSpecs", () => {
  const realLoader: ScenarioLoaderPlugin = {
    name: "scenario-loader:openapi",
    async init() {},
    loadScenarios: loadOpenApiScenarios,
  };

  function writeTmpSpec(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gevanni-spec-"));
    const file = path.join(dir, "spec.json");
    const spec = {
      openapi: "3.0.0",
      info: { title: "T", version: "1" },
      paths: { "/a": { get: { operationId: "opA" } } },
      "x-gevanni-scenarios": [{ id: "s1", steps: ["opA"] }],
    };
    fs.writeFileSync(file, JSON.stringify(spec));
    return file;
  }

  it("throws on an unknown loader name", async () => {
    const registry = makeRegistry(undefined);
    await expect(
      loadScenariosFromSpecs(["unknown:./x.yaml"], registry as PluginRegistry),
    ).rejects.toThrow(/Unknown scenario loader: "unknown"/);
  });

  it("throws when the path expands to no files", async () => {
    const registry = makeRegistry(realLoader);
    await expect(
      loadScenariosFromSpecs(
        ["openapi:./does-not-exist-*.yaml"],
        registry as PluginRegistry,
      ),
    ).rejects.toThrow(/No scenario files found/);
  });

  it("loads scenarios via the named loader", async () => {
    const file = writeTmpSpec();
    const registry = makeRegistry(realLoader);
    const scenarios = await loadScenariosFromSpecs(
      [`openapi:${file}`],
      registry as PluginRegistry,
    );
    expect(scenarios).toHaveLength(1);
    expect(scenarios[0].name).toBe("s1");
    fs.rmSync(path.dirname(file), { recursive: true });
  });
});
