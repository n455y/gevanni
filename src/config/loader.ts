import fs from "node:fs";
import path from "node:path";
import type { PluginConfig } from "../types/models.js";
import type { LogLevel } from "../core/logger.js";

interface ResolvedConfig {
  concurrency: number;
  plugins: PluginConfig[];
  scenarioPaths: string[];
  logLevel: LogLevel;
}

interface RawConfig {
  concurrency?: number;
  plugins?: PluginConfig[];
  scenarioPaths?: string[];
  logLevel?: LogLevel;
}

const DEFAULT_CONCURRENCY = 5;
const DEFAULT_LOG_LEVEL: LogLevel = "info";

const DEFAULT_CONFIG: ResolvedConfig = {
  concurrency: DEFAULT_CONCURRENCY,
  logLevel: DEFAULT_LOG_LEVEL,
  plugins: [],
  scenarioPaths: [],
};

function loadConfig(
  configPath?: string,
  cliOverrides?: Partial<ResolvedConfig>,
): ResolvedConfig {
  const resolvedPath = configPath ?? path.resolve("./gevanni.json");

  let fileConfig: RawConfig = {};

  try {
    const raw = fs.readFileSync(resolvedPath, "utf-8");
    fileConfig = JSON.parse(raw) as RawConfig;
  } catch {
    // File doesn't exist or is invalid JSON -- use defaults
  }

  const resolved: ResolvedConfig = {
    concurrency: cliOverrides?.concurrency ?? fileConfig.concurrency ?? DEFAULT_CONFIG.concurrency,
    logLevel: cliOverrides?.logLevel ?? fileConfig.logLevel ?? DEFAULT_CONFIG.logLevel,
    plugins: cliOverrides?.plugins ?? fileConfig.plugins ?? DEFAULT_CONFIG.plugins,
    scenarioPaths: cliOverrides?.scenarioPaths ?? fileConfig.scenarioPaths ?? DEFAULT_CONFIG.scenarioPaths,
  };

  return resolved;
}

export { loadConfig, type ResolvedConfig, type RawConfig };
