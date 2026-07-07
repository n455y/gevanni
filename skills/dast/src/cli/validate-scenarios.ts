/**
 * validate-scenarios — 生成されたシナリオの遷移を実際のHTTPリクエストで検証する。
 *
 * CLI から `gevanni validate-scenarios -s <loader>:<path>` で実行する。
 *
 * プラグインレジストリ経由でシナリオをロードし、対応する scenario プラグインに
 * 検証を委譲する。特定のフォーマット（OpenAPI 等）に依存しない汎用的な設計。
 */

import { loadScenariosFromSpecs } from "./scenario-spec.ts";
import type {
  PluginRegistry,
  ScenarioPlugin,
  ScenarioValidationResult,
} from "../core/plugin.ts";

// --- Console output ---

function printValidationReport(results: ScenarioValidationResult[]): void {
  for (const result of results) {
    console.log(`▶ Running: ${result.scenarioName}`);
    for (const step of result.steps) {
      if (step.success) {
        console.log(`  ✅ ${step.description} → ${step.statusCode}`);
        for (const t of step.transitions) {
          if (t.resolved) {
            console.log(
              `     🔗 Link → ${t.description}: ${t.resolvedValue?.substring(0, 50)}`,
            );
          } else {
            console.log(`     ⚠️  Link → ${t.description}: ${t.error}`);
          }
        }
      } else {
        console.log(`  ❌ ${step.description}: ${step.error}`);
      }
    }
    console.log("");
  }

  // --- Summary ---
  const totalSteps = results.reduce((sum, r) => sum + r.steps.length, 0);
  const passedSteps = results.reduce(
    (sum, r) => sum + r.steps.filter((s) => s.success).length,
    0,
  );
  const totalTransitions = results.reduce(
    (sum, r) =>
      sum + r.steps.reduce((s, step) => s + step.transitions.length, 0),
    0,
  );
  const resolvedTransitions = results.reduce(
    (sum, r) =>
      sum +
      r.steps.reduce(
        (s, step) => s + step.transitions.filter((t) => t.resolved).length,
        0,
      ),
    0,
  );
  const allPassed = results.every((r) => r.allValid);

  console.log("═══════════════════════════════════════");
  console.log("🔗 Scenario transition integrity:");
  console.log(`   • Scenarios checked:     ${results.length}`);
  console.log(
    `   • Multi-step scenarios:  ${results.filter((r) => r.steps.length > 1).length}`,
  );
  console.log(`   • Total step executions: ${totalSteps}`);
  console.log(`   • ✅ Successful steps:   ${passedSteps}`);
  console.log(`   • ❌ Failed steps:       ${totalSteps - passedSteps}`);
  console.log(`   • 🔗 Transitions checked: ${totalTransitions}`);
  console.log(`   • ✅ Resolved transitions: ${resolvedTransitions}`);
  console.log(
    `   • ⚠️  Unresolved transitions: ${totalTransitions - resolvedTransitions}`,
  );
  console.log("═══════════════════════════════════════");

  if (allPassed) {
    console.log("\n✅ All scenario transitions are valid.");
  } else {
    console.log("\n❌ Some transitions failed. Review the errors above.");
  }
}

// --- Main entry point ---

export async function validateScenarios(
  specs: string[],
  registry: PluginRegistry,
  upstream?: string,
): Promise<{ allPassed: boolean; results: ScenarioValidationResult[] }> {
  if (specs.length === 0) {
    throw new Error("No scenario sources specified.");
  }

  // 1. Load scenarios via plugin registry (generic)
  const scenarios = await loadScenariosFromSpecs(specs, registry);

  console.log("🔗 Validating scenario transitions...\n");
  if (upstream) {
    console.log(`🔀 Upstream proxy: ${upstream}`);
  }
  console.log("");

  if (scenarios.length === 0) {
    console.log("⚠️  No scenarios found in spec.");
    return { allPassed: true, results: [] };
  }

  console.log(`📋 Found ${scenarios.length} scenario(s)\n`);

  // 2. For each scenario, find the scenario plugin and validate
  const results: ScenarioValidationResult[] = [];
  for (const scenario of scenarios) {
    const pluginName = `scenario:${scenario.type}`;
    const plugin = registry.getByName<ScenarioPlugin>(pluginName);
    if (!plugin) {
      throw new Error(
        `No scenario plugin found for type "${scenario.type}". ` +
          `Expected a plugin named "${pluginName}".`,
      );
    }
    if (!plugin.validateScenario) {
      throw new Error(
        `The scenario plugin "${pluginName}" does not support validation.`,
      );
    }
    const result = await plugin.validateScenario(scenario, {
      upstreamProxyUrl: upstream,
    });
    results.push(result);
  }

  // 3. Print results
  printValidationReport(results);

  const allPassed = results.every((r) => r.allValid);
  return { allPassed, results };
}
