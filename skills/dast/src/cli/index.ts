import path from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { PluginRegistryImpl } from "../core/plugin.ts";
import { RuntimeContext } from "../core/runtime-context.ts";
import { createLogger } from "../core/logger.ts";
import { loadConfig } from "../config/loader.ts";
import { loadPlugins } from "../config/plugin-loader.ts";
import { registerAllBuiltinPlugins } from "../builtin.ts";
import { Orchestrator } from "../core/orchestrator.ts";
import { ScanId } from "../types/branded.ts";
import type { LogLevel } from "../core/logger.ts";
import type { ScenarioLoaderPlugin } from "../core/plugin.ts";
import type { Scenario } from "../types/models.ts";
import { loadScenariosFromSpecs } from "./scenario-spec.ts";

// config 経路（plan/resume/report）用: scenarioSources を全 scenario-loader で自動判定。
// 形式や挙動は従来（空配列フォールバック）を維持する。
async function loadScenarios(
  sources: unknown[],
  loaders: ScenarioLoaderPlugin[],
): Promise<Scenario[]> {
  const scenarios: Scenario[] = [];
  for (const source of sources) {
    for (const loader of loaders) {
      scenarios.push(...(await loader.loadScenarios(source)));
    }
  }
  return scenarios;
}

interface CliOptions {
  config?: string;
  verbose?: boolean;
  quiet?: boolean;
  concurrency?: string;
}

function buildOverrides(
  opts: CliOptions,
): Partial<{ logLevel: LogLevel; concurrency: number }> {
  const overrides: Partial<{ logLevel: LogLevel; concurrency: number }> = {};

  if (opts.verbose) {
    overrides.logLevel = "debug";
  } else if (opts.quiet) {
    overrides.logLevel = "error";
  }

  if (opts.concurrency) {
    overrides.concurrency = parseInt(opts.concurrency, 10);
  }

  return overrides;
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

interface ReporterConfig {
  name: string;
  options?: string;
}

function parseReporterFlags(flags: string[]): ReporterConfig[] {
  if (flags.length === 0) {
    return [{ name: "console", options: undefined }];
  }

  return flags.map((flag) => {
    const colonIndex = flag.indexOf(":");
    if (colonIndex === -1) {
      return { name: flag, options: undefined };
    }
    const name = flag.slice(0, colonIndex);
    const options = flag.slice(colonIndex + 1);
    return { name, options };
  });
}

// Exported for testing and reuse
export type { ReporterConfig };
export { parseReporterFlags };

async function bootstrap(
  configPath?: string,
  cliOverrides?: Partial<{ logLevel: LogLevel; concurrency: number }>,
) {
  const { config, configDir } = loadConfig(configPath, cliOverrides);
  const logger = createLogger(config.logLevel);
  const ctx = new RuntimeContext({ logger });
  const registry = new PluginRegistryImpl();

  await loadPlugins(config.plugins, registry, configDir);
  const plugins = await registry.initializeAll(ctx);
  ctx.pluginRegistry = registry;
  const loaders = plugins.filter(
    (p): p is ScenarioLoaderPlugin => p.name.startsWith("scenario-loader:"),
  );

  const orchestrator = new Orchestrator({
    context: ctx,
  });
  return { config, configDir, logger, ctx, registry, orchestrator, loaders };
}

// CLI setup
const program = new Command();
program
  .name("gevanni")
  .description("CLI-based web application vulnerability scanner")
  .version("0.1.0");

// scan command
program
  .command("scan")
  .description("Run full vulnerability scan from scenario source(s)")
  .option("--config <path>", "Config file path")
  .option(
    "-s, --scenario <name>:<path>",
    "Scenario source as <loader-name>:<path>, e.g. openapi:./spec.yaml (repeatable, glob/dir ok)",
    collect,
    [] as string[],
  )
  .option("--verbose", "Debug logging")
  .option("--quiet", "Minimal logging")
  .option("--concurrency <n>", "Parallel workers")
  .option(
    "-r, --reporter <name[:option]>",
    "Reporter to use (repeatable, e.g., --reporter json:report.json)",
    collect,
    [] as string[],
  )
  .action(async (opts: { config?: string; scenario: string[]; verbose?: boolean; quiet?: boolean; concurrency?: string; reporter: string[] }) => {
    // モード決定: config.json 使用時
    if (opts.config) {
      const { config, configDir, orchestrator, registry } = await bootstrap(opts.config, buildOverrides(opts));

      // config.scenarios を scenario specs に変換（configDirを考慮）
      const scenarioSpecs = config.scenarios.map((s) => {
        const resolvedPath = path.resolve(configDir, s.file);
        return `${s.type}:${resolvedPath}`;
      });

      // シナリオ読み込み（registryからloaderを取得）
      const scenarios = await loadScenariosFromSpecs(scenarioSpecs, registry);

      if (scenarios.length === 0) {
        const logger = createLogger(config.logLevel);
        logger.error("No scenarios loaded from config file");
        process.exit(1);
      }

      // スキャン実行
      const reporterConfigs = parseReporterFlags(opts.reporter ?? []);
      const { scanId, items } = await orchestrator.plan(scenarios);
      await orchestrator.scan(scanId, items, config.concurrency);
      await orchestrator.report(scanId, reporterConfigs);
      return;
    }

    // モード2: CLIオプション直接指定時（既存の実装）
    if (opts.scenario.length === 0) {
      console.error("error: required option '-s, --scenario <name>:<path>' not specified");
      process.exit(1);
    }

    const logLevel = opts.verbose ? "debug" : opts.quiet ? "error" : "info";
    const logger = createLogger(logLevel);
    const ctx = new RuntimeContext({ logger });
    const registry = new PluginRegistryImpl();

    // 全ビルトインプラグインを登録。proxy:http の upstream は未指定 =
    // シナリオの URL（OpenAPI の servers[0].url 起）のホストへ直接アクセス。
    registerAllBuiltinPlugins(registry);
    await registry.initializeAll(ctx);
    ctx.pluginRegistry = registry;

    const scenarios = await loadScenariosFromSpecs(opts.scenario, registry);
    if (scenarios.length === 0) {
      logger.error("No scenarios loaded from the given --scenario input(s)");
      process.exit(1);
    }

    const orchestrator = new Orchestrator({ context: ctx });
    const concurrency = opts.concurrency ? parseInt(opts.concurrency, 10) : 5;
    const reporterConfigs = parseReporterFlags(opts.reporter ?? []);
    const { scanId, items } = await orchestrator.plan(scenarios);
    await orchestrator.scan(scanId, items, concurrency);
    await orchestrator.report(scanId, reporterConfigs);
  });

// plan command
program
  .command("plan")
  .description("Create scan plan only")
  .option("--config <path>", "Config file path")
  .option("--verbose", "Debug logging")
  .option("--quiet", "Minimal logging")
  .action(async (opts: CliOptions) => {
    const { config, orchestrator, loaders } = await bootstrap(
      opts.config,
      buildOverrides(opts),
    );
    // scenarios → "type:file" 形式に変換
    const scenarioSpecs = config.scenarios.map((s) => `${s.type}:${s.file}`);
    const scenarios = await loadScenarios(scenarioSpecs, loaders);
    await orchestrator.plan(scenarios);
  });

// resume command
program
  .command("resume [scanId]")
  .description("Resume interrupted scan")
  .option("--config <path>", "Config file path")
  .option("--verbose", "Debug logging")
  .option("--quiet", "Minimal logging")
  .option("--concurrency <n>", "Parallel workers")
  .action(async (scanId: string | undefined, opts: CliOptions) => {
    const { config, orchestrator } = await bootstrap(
      opts.config,
      buildOverrides(opts),
    );
    await orchestrator.resume(scanId ? ScanId(scanId) : undefined, config.concurrency);
  });

// report command
program
  .command("report [scanId]")
  .description("Regenerate report from saved results")
  .option("--config <path>", "Config file path")
  .option("--verbose", "Debug logging")
  .option("--quiet", "Minimal logging")
  .option(
    "-r, --reporter <name[:option]>",
    "Reporter to use (repeatable)",
    collect,
    [] as string[],
  )
  .action(async (scanId: string | undefined, opts: any) => {
    const { orchestrator } = await bootstrap(
      opts.config,
      buildOverrides(opts),
    );
    const reporterConfigs = parseReporterFlags(opts.reporter ?? []);
    await orchestrator.report(ScanId(scanId!), reporterConfigs);
  });

// plugins command
program
  .command("plugins")
  .description("List registered plugins")
  .option("--config <path>", "Config file path")
  .action(async (opts: CliOptions) => {
    const { config } = await bootstrap(opts.config);
    for (const plugin of config.plugins) {
      if (plugin === ":builtin:") {
        console.log(":builtin: (all builtin plugins)");
      } else if (typeof plugin === "string") {
        console.log(plugin);
      } else {
        console.log(`${plugin.file} with options`);
      }
    }
  });

// Only parse argv when run directly (not when imported, e.g. in tests)
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  program.parse();
}
