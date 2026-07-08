import type { PluginRegistry, ScenarioLoaderPlugin } from "../core/plugin.ts";
import type { Scenario } from "../types/models.ts";
import { expandScenarioPaths } from "./scenario-paths.ts";

export interface ScenarioSpec {
  loaderName: string;
  path: string;
}

// Parse a "-s <loader-name>:<path>" spec.
// Split on the first colon (path may contain colons).
export function parseScenarioSpec(spec: string): ScenarioSpec {
  const idx = spec.indexOf(":");
  if (idx <= 0) {
    throw new Error(
      `Invalid scenario spec "${spec}": expected <loader-name>:<path> (e.g. openapi:./spec.yaml)`,
    );
  }
  return { loaderName: spec.slice(0, idx), path: spec.slice(idx + 1) };
}

// Parse each spec, resolve the corresponding scenario-loader from the registry, and load.
// Missing name, unknown name, or zero expanded paths are immediate errors (no auto-detect fallback).
export async function loadScenariosFromSpecs(
  specs: string[],
  registry: PluginRegistry,
): Promise<Scenario[]> {
  const scenarios: Scenario[] = [];
  for (const spec of specs) {
    const { loaderName, path } = parseScenarioSpec(spec);
    const loader = registry.getByName<ScenarioLoaderPlugin>(
      `scenario-loader:${loaderName}`,
    );
    if (!loader) {
      throw new Error(
        `Unknown scenario loader: "${loaderName}" (available: openapi)`,
      );
    }
    const files = expandScenarioPaths([path]);
    if (files.length === 0) {
      throw new Error(`No scenario files found for --scenario "${spec}"`);
    }
    for (const file of files) {
      scenarios.push(...(await loader.loadScenarios(file)));
    }
  }
  return scenarios;
}
