import { Command } from "commander";
import { InMemoryCommandBus } from "../core/command-bus.js";
import { InMemoryEventBus } from "../core/event-bus.js";
import { PluginRegistryImpl } from "../core/plugin.js";
import { createLogger } from "../core/logger.js";
import { loadConfig } from "../config/loader.js";
import { registerBuiltinPlugins } from "../builtin.js";
import { Orchestrator } from "../core/orchestrator.js";
import type { LogLevel } from "../core/logger.js";

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
  await registry.initializeAll({
    commandBus,
    eventBus,
    pluginConfigs: config.plugins,
  });

  const orchestrator = new Orchestrator({ commandBus, eventBus, logger });
  return { config, logger, commandBus, eventBus, registry, orchestrator };
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
    const { config, logger, orchestrator } = await bootstrap(
      opts.config,
      overrides,
    );
    const { scanId, inspectors } = await orchestrator.plan(
      config.scenarioPaths,
    );
    await orchestrator.scan(scanId, inspectors, config.concurrency);
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
    await orchestrator.plan(config.scenarioPaths);
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
