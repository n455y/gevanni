import { Command } from "commander";
import { PluginRegistryImpl } from "../core/plugin.ts";
import { RuntimeContext } from "../core/runtime-context.ts";
import { createLogger } from "../core/logger.ts";
import { loadConfig } from "../config/loader.ts";
import { builtinPluginFactories, registerAllBuiltinPlugins } from "../builtin.ts";
import { Orchestrator } from "../core/orchestrator.ts";
import { ScanId } from "../types/branded.ts";
import type { LogLevel } from "../core/logger.ts";
import { loadOpenApiScenarios } from "../plugins/loader/openapi-loader.ts";
import type { Scenario } from "../types/models.ts";
import { expandScenarioPaths } from "./scenario-paths.ts";

const scenarioLoaders = [loadOpenApiScenarios];

async function loadScenarios(sources: unknown[]): Promise<Scenario[]> {
  const scenarios: Scenario[] = [];
  for (const source of sources) {
    for (const loader of scenarioLoaders) {
      const loaded = await loader(source);
      scenarios.push(...loaded);
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

async function bootstrap(
  configPath?: string,
  cliOverrides?: Partial<{ logLevel: LogLevel; concurrency: number }>,
) {
  const config = loadConfig(configPath, cliOverrides);
  const logger = createLogger(config.logLevel);
  const ctx = new RuntimeContext({ logger });
  const registry = new PluginRegistryImpl();

  for (const pc of config.plugins) {
    const factory = builtinPluginFactories.get(pc.name);
    if (!factory) {
      throw new Error(`Unknown plugin: ${pc.name}`);
    }
    registry.register(factory(pc.options));
  }
  await registry.initializeAll(ctx);

  const orchestrator = new Orchestrator({
    context: ctx,
  });
  return { config, logger, ctx, registry, orchestrator };
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
  .option(
    "-s, --scenario <path>",
    "Scenario source file/glob/dir (repeatable)",
    collect,
    [] as string[],
  )
  .option("--verbose", "Debug logging")
  .option("--quiet", "Minimal logging")
  .option("--concurrency <n>", "Parallel workers")
  .action(async (opts: { scenario: string[]; verbose?: boolean; quiet?: boolean; concurrency?: string }) => {
    if (opts.scenario.length === 0) {
      console.error("error: required option '-s, --scenario <path>' not specified");
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

    const paths = expandScenarioPaths(opts.scenario);
    if (paths.length === 0) {
      logger.error("No scenario files found for the given --scenario input(s)");
      process.exit(1);
    }

    const scenarios = await loadScenarios(paths);
    const orchestrator = new Orchestrator({ context: ctx });
    const concurrency = opts.concurrency ? parseInt(opts.concurrency, 10) : 5;
    const { scanId, items } = await orchestrator.plan(scenarios);
    await orchestrator.scan(scanId, items, concurrency);
    await orchestrator.report(scanId);
  });

// plan command
program
  .command("plan")
  .description("Create scan plan only")
  .option("--config <path>", "Config file path")
  .option("--verbose", "Debug logging")
  .option("--quiet", "Minimal logging")
  .action(async (opts: CliOptions) => {
    const { config, orchestrator } = await bootstrap(
      opts.config,
      buildOverrides(opts),
    );
    const scenarios = await loadScenarios(config.scenarioSources);
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
  .action(async (scanId: string | undefined, opts: CliOptions) => {
    const { orchestrator } = await bootstrap(
      opts.config,
      buildOverrides(opts),
    );
    await orchestrator.report(ScanId(scanId!));
  });

// plugins command
program
  .command("plugins")
  .description("List registered plugins")
  .option("--config <path>", "Config file path")
  .action(async (opts: CliOptions) => {
    const { config } = await bootstrap(opts.config);
    for (const plugin of config.plugins) {
      console.log(plugin.name);
    }
  });

program.parse();
