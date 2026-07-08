import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { PluginRegistryImpl } from "../core/plugin.ts";
import { RuntimeContext } from "../core/runtime-context.ts";
import { createLogger } from "../core/logger.ts";
import { loadConfig } from "../config/loader.ts";
import {
  loadPlugins,
  discoverPluginFiles,
  resolvePluginPath,
} from "../config/plugin-loader.ts";
import { Orchestrator } from "../core/orchestrator.ts";
import { ScanId } from "../types/branded.ts";
import type { LogLevel } from "../core/logger.ts";
import type { ScenarioLoaderPlugin } from "../core/plugin.ts";
import type { Scenario } from "../types/models.ts";
import { loadScenariosFromSpecs } from "./scenario-spec.ts";
import { validateScenarios } from "./validate-scenarios.ts";

// config path (plan/resume/report): auto-detect scenarioSources across all scenario-loaders.
// Format and behavior match the legacy path (empty array fallback).
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

  // Plugin search base directories (in priority order)
  // 1. .gevanni/plugins/
  // 2. current working directory
  // 3. directory containing the config file
  const searchDirs = [
    path.join(process.cwd(), ".gevanni", "plugins"),
    process.cwd(),
    configDir,
  ];

  // Auto-discover plugins from plugins/autoload/ in each search directory
  // Prioritize explicitly specified plugins (load config → auto-discovered order)
  const autoloadBaseDirs = [
    path.join(process.cwd(), ".gevanni"),
    process.cwd(),
    configDir,
  ];
  const discovered = discoverPluginFiles(...autoloadBaseDirs);
  const explicitPaths = new Set(
    config.plugins
      .filter((p): p is string => typeof p === "string" && p !== ":builtin:")
      .map((p) => resolvePluginPath(p, searchDirs))
      .filter((p): p is string => p !== null),
  );
  const newPlugins = discovered.filter((p) => {
    if (typeof p !== "string") return false;
    return !explicitPaths.has(p);
  });
  const allPlugins = [...config.plugins, ...newPlugins];

  await loadPlugins(allPlugins, registry, searchDirs);
  const plugins = await registry.initializeAll(ctx);
  ctx.pluginRegistry = registry;
  const loaders = plugins.filter((p): p is ScenarioLoaderPlugin =>
    p.name.startsWith("scenario-loader:"),
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
  .action(
    async (opts: {
      config?: string;
      scenario: string[];
      verbose?: boolean;
      quiet?: boolean;
      concurrency?: string;
      reporter: string[];
    }) => {
      const { config, configDir, logger, orchestrator, registry } =
        await bootstrap(opts.config, buildOverrides(opts));

      // Scenario sources: prefer --scenario flag if provided, otherwise fall back to config
      const scenarioSpecs: string[] =
        opts.scenario.length > 0
          ? opts.scenario
          : config.scenarios.map((s) => {
              // Try cwd first, fall back to configDir
              const cwdPath = path.resolve(s.file);
              const resolvedPath = fs.existsSync(cwdPath)
                ? cwdPath
                : path.resolve(configDir, s.file);
              return `${s.type}:${resolvedPath}`;
            });

      if (scenarioSpecs.length === 0) {
        logger.error(
          "No scenario sources specified. Use --scenario or configure scenarios in config file.",
        );
        process.exit(1);
      }

      const scenarios = await loadScenariosFromSpecs(scenarioSpecs, registry);
      if (scenarios.length === 0) {
        logger.error("No scenarios loaded from the given source(s)");
        process.exit(1);
      }

      const reporterConfigs = parseReporterFlags(opts.reporter ?? []);
      const { scanId, items } = await orchestrator.plan(scenarios);
      await orchestrator.scan(scanId, items, config.concurrency);
      await orchestrator.report(scanId, reporterConfigs);
    },
  );

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
    // scenarios → convert to "type:file" format
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
    await orchestrator.resume(
      scanId ? ScanId(scanId) : undefined,
      config.concurrency,
    );
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
    const { orchestrator } = await bootstrap(opts.config, buildOverrides(opts));
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
        const label = "file" in plugin ? plugin.file : plugin.name;
        console.log(`${label} with options`);
      }
    }
  });

// validate-scenarios command
program
  .command("validate-scenarios")
  .description("Validate scenario transitions with actual HTTP requests")
  .option("--config <path>", "Config file path")
  .option(
    "-s, --scenario <name>:<path>",
    "Scenario source as <loader-name>:<path>, e.g. openapi:./spec.yaml (repeatable)",
    collect,
    [] as string[],
  )
  .option("--upstream <url>", "Upstream proxy URL (e.g. http://127.0.0.1:8080)")
  .action(
    async (opts: {
      config?: string;
      scenario: string[];
      upstream?: string;
    }) => {
      const { registry } = await bootstrap(opts.config);
      if (opts.scenario.length === 0) {
        console.error(
          "No scenario sources specified. Use --scenario/-s (e.g. -s openapi:./spec.yaml)",
        );
        process.exit(1);
      }
      try {
        const upstream = opts.upstream ?? process.env.HTTP_PROXY;
        const { allPassed } = await validateScenarios(
          opts.scenario,
          registry,
          upstream,
        );
        if (!allPassed) process.exit(1);
      } catch (err) {
        console.error(
          `❌ Validation failed: ${err instanceof Error ? err.message : String(err)}`,
        );
        process.exit(1);
      }
    },
  );

// Only parse argv when run directly (not when imported, e.g. in tests)
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  program.parse();
}
