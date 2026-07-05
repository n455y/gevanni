import fs from "node:fs";
import path from "node:path";
import { registerAllBuiltinPlugins } from "../builtin.ts";
import type { PluginRegistry } from "../core/plugin.ts";
import type { PluginSpec } from "./loader.ts";

/**
 * PluginSpec 配列を解決して PluginRegistry に登録する。
 * 同名プラグインは後勝ち（Map.set の仕様）。
 *
 * @param specs - PluginSpec 配列
 * @param registry - プラグインレジストリ
 * @param searchDirs - プラグインファイルの検索基準ディレクトリ（優先度順）
 */
export async function loadPlugins(
  specs: PluginSpec[],
  registry: PluginRegistry,
  searchDirs: string[],
): Promise<void> {
  for (const spec of specs) {
    if (spec === ":builtin:") {
      // 全ビルトインプラグインを登録
      registerAllBuiltinPlugins(registry);
    } else if (typeof spec === "string") {
      // ファイルから default export クラスを new() して登録
      const Cls = await loadPluginClass(spec, searchDirs);
      registry.register(new Cls());
    } else {
      // options 付きで new()
      const Cls = await loadPluginClass(spec.file, searchDirs);
      registry.register(new Cls(spec.options));
    }
  }
}

/**
 * 複数の検索ディレクトリからプラグインファイルの絶対パスを解決する。
 * 最初に見つかったパスを返す。見つからない場合は null。
 *
 * @param file - プラグインファイルの相対パス
 * @param searchDirs - 検索基準ディレクトリのリスト（優先度順）
 * @returns 解決された絶対パス、または null
 */
export function resolvePluginPath(
  file: string,
  searchDirs: string[],
): string | null {
  for (const dir of searchDirs) {
    const resolvedPath = path.resolve(dir, file);
    if (fs.existsSync(resolvedPath)) {
      return resolvedPath;
    }
  }
  return null;
}

/**
 * 複数の検索ディレクトリからプラグインファイルを探し、
 * default export クラスを読み込む。
 *
 * @param file - プラグインファイルのパス（searchDirs 基準）
 * @param searchDirs - 検索基準ディレクトリのリスト（優先度順）
 * @returns プラグインクラスのコンストラクタ
 * @throws ファイル not found, default export なし, クラスでない場合
 */
async function loadPluginClass(
  file: string,
  searchDirs: string[],
): Promise<new (...args: unknown[]) => InstanceType<never>> {
  const resolvedPath = resolvePluginPath(file, searchDirs);
  if (!resolvedPath) {
    throw new Error(
      `Plugin file "${file}" not found in any search directory: ${searchDirs.join(", ")}`,
    );
  }

  let mod: unknown;
  try {
    mod = await import(resolvedPath);
  } catch (e) {
    throw new Error(
      `Failed to import plugin file "${resolvedPath}": ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  // default export をチェック
  if (mod === null || typeof mod !== "object" || !("default" in mod)) {
    throw new Error(`Plugin file "${resolvedPath}" has no default export`);
  }
  const Cls = (mod as { default: unknown }).default;

  // クラス（コンストラクタ）をチェック
  if (typeof Cls !== "function" || Cls.toString().startsWith("class") === false) {
    throw new Error(
      `Default export of "${resolvedPath}" is not a class (constructor)`,
    );
  }

  return Cls as new (...args: unknown[]) => InstanceType<never>;
}

/**
 * 指定されたディレクトリ群の plugins/autoload/ 内の .ts / .js ファイルを
 * PluginSpec 配列として自動検出する。
 * 各ディレクトリの plugins/autoload/ が存在しない場合はスキップ。
 *
 * 返されるパスは絶対パス。重複は除外され、ファイル名でソートされる。
 *
 * @param searchDirs - 検索対象の親ディレクトリ群（例: configDir, cwd/.gevanni）
 * @returns 検出されたプラグインファイルの絶対パス PluginSpec 配列
 */
export function discoverPluginFiles(...searchDirs: string[]): PluginSpec[] {
  const seen = new Set<string>();
  const results: string[] = [];
  for (const dir of searchDirs) {
    const pluginsDir = path.join(dir, "plugins", "autoload");
    let entries: string[];
    try {
      entries = fs.readdirSync(pluginsDir);
    } catch {
      continue;
    }
    for (const f of entries) {
      if (
        (!f.endsWith(".ts") && !f.endsWith(".js")) ||
        f.startsWith(".")
      ) {
        continue;
      }
      const absPath = path.resolve(pluginsDir, f);
      if (seen.has(absPath)) continue;
      seen.add(absPath);
      results.push(absPath);
    }
  }
  // ファイル名でソート（決定論的な順序）
  results.sort((a, b) => path.basename(a).localeCompare(path.basename(b)));
  return results;
}
