import fs from "node:fs";
import path from "node:path";
import type { LogLevel } from "../core/logger.ts";

/**
 * プラグイン指定の形式
 * - ":builtin:": 全ビルトインプラグイン
 * - string: ファイルパス (./.gevanni/plugins/custom.ts)
 * - {file, options}: options 付きファイル指定
 */
export type PluginSpec =
  | ":builtin:"
  | string
  | { file: string; options: Record<string, unknown> };

/**
 * シナリオ指定の形式
 * - type: "openapi", "graphql", etc.
 * - file: ファイルパス
 */
export interface ScenarioSpec {
  type: string;
  file: string;
}

export interface ResolvedConfig {
  concurrency: number;
  plugins: PluginSpec[];
  scenarios: ScenarioSpec[];
  logLevel: LogLevel;
}

export interface RawConfig {
  concurrency?: number;
  plugins?: PluginSpec[];
  scenarios?: ScenarioSpec[];
  logLevel?: LogLevel;
}

const DEFAULT_CONCURRENCY = 5;
const DEFAULT_LOG_LEVEL: LogLevel = "info";

const DEFAULT_CONFIG: ResolvedConfig = {
  concurrency: DEFAULT_CONCURRENCY,
  logLevel: DEFAULT_LOG_LEVEL,
  plugins: [],
  scenarios: [],
};

export function loadConfig(
  configPath?: string,
  cliOverrides?: Partial<Omit<ResolvedConfig, "plugins" | "scenarios">>,
): { config: ResolvedConfig; configDir: string } {
  const resolvedPath = configPath ?? path.resolve("./gevanni.json");
  const configDir = path.dirname(resolvedPath);

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
    plugins: fileConfig.plugins ?? DEFAULT_CONFIG.plugins,
    scenarios: fileConfig.scenarios ?? DEFAULT_CONFIG.scenarios,
  };

  return { config: resolved, configDir };
}
