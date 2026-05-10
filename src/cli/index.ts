import { Command } from "commander";
import { InMemoryCommandBus } from "../core/command-bus.ts";
import { InMemoryEventBus } from "../core/event-bus.ts";
import { PluginRegistryImpl } from "../core/plugin.ts";
import { createLogger } from "../core/logger.ts";
import { loadConfig } from "../config/loader.ts";
import { registerBuiltinPlugins } from "../builtin.ts";
import { Orchestrator } from "../core/orchestrator.ts";
import type { LogLevel } from "../core/logger.ts";
import type { ScenarioLoaderPlugin } from "../core/plugin.ts";
import type { Scenario } from "../types/models.ts";

interface CliOptions {
  config?: string;
  verbose?: boolean;
  quiet?: boolean;
  concurrency?: string;
}

async function loadScenarios(
  loaders: ScenarioLoaderPlugin[],
  scenarioSources: unknown[],
): Promise<Scenario[]> {
  const scenarios: Scenario[] = [];
  for (const source of scenarioSources) {
    for (const loader of loaders) {
      const loaded = await loader.load(source);
      scenarios.push(...loaded);
    }
  }
  return scenarios;
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

async function bootstrap(
  configPath?: string,
  cliOverrides?: Partial<{ logLevel: LogLevel; concurrency: number }>,
) {
  const config = loadConfig(configPath, cliOverrides);
  const logger = createLogger(config.logLevel);
  const commandBus = new InMemoryCommandBus();
  const eventBus = new InMemoryEventBus();
  const registry = new PluginRegistryImpl();

  registerBuiltinPlugins(registry);
  const plugins = await registry.initializeAll({
    commandBus,
    eventBus,
    pluginConfigs: config.plugins,
  });

  const loaders = plugins.filter(
    (p): p is ScenarioLoaderPlugin => "load" in p && typeof (p as any).load === "function",
  );

  const orchestrator = new Orchestrator({ commandBus, eventBus, logger });
  return { config, logger, commandBus, eventBus, registry, orchestrator, loaders };
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
  .description("Run full vulnerability scan")
  .option("--config <path>", "Config file path")
  .option("--verbose", "Debug logging")
  .option("--quiet", "Minimal logging")
  .option("--concurrency <n>", "Parallel workers")
  .action(async (opts: CliOptions) => {
    const overrides = buildOverrides(opts);
    const { config, logger, orchestrator, loaders } = await bootstrap(
      opts.config,
      overrides,
    );
    const scenarios = await loadScenarios(loaders, config.scenarioSources);
    const { scanId, items } = await orchestrator.plan(scenarios);
    await orchestrator.scan(scanId, items, config.concurrency);
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
    const { config, orchestrator, loaders } = await bootstrap(
      opts.config,
      buildOverrides(opts),
    );
    const scenarios = await loadScenarios(loaders, config.scenarioSources);
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
    await orchestrator.resume(scanId as any, config.concurrency);
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
    await orchestrator.report(scanId as any);
  });

// plugins command
program
  .command("plugins")
  .description("List registered plugins")
  .option("--config <path>", "Config file path")
  .action(async (opts: CliOptions) => {
    const { config } = await bootstrap(opts.config);
    for (const plugin of config.plugins) {
      console.log(`${plugin.type}/${plugin.name}`);
    }
  });

program.parse();
