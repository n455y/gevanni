import type { PluginRegistry, ScenarioLoaderPlugin } from "../core/plugin.ts";
import type { Scenario } from "../types/models.ts";
import { expandScenarioPaths } from "./scenario-paths.ts";

export interface ScenarioSpec {
  loaderName: string;
  path: string;
}

// "-s <loader-name>:<path>" 形式の spec をパースする。
// 最初のコロンで分割する（path 側にコロンが含まれていても可）。
export function parseScenarioSpec(spec: string): ScenarioSpec {
  const idx = spec.indexOf(":");
  if (idx <= 0) {
    throw new Error(
      `Invalid scenario spec "${spec}": expected <loader-name>:<path> (e.g. openapi:./spec.yaml)`,
    );
  }
  return { loaderName: spec.slice(0, idx), path: spec.slice(idx + 1) };
}

// 各 spec をパースし、registry から対応する scenario-loader を取得して読み込む。
// 名前省略・未知名・path 展開0件は即エラー（自動判定フォールバックなし）。
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
