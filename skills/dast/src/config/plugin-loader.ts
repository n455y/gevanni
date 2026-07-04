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
 * @param configDir - config ファイルのあるディレクトリ（相対パス解決用）
 */
export async function loadPlugins(
  specs: PluginSpec[],
  registry: PluginRegistry,
  configDir: string,
): Promise<void> {
  for (const spec of specs) {
    if (spec === ":builtin:") {
      // 全ビルトインプラグインを登録
      registerAllBuiltinPlugins(registry);
    } else if (typeof spec === "string") {
      // ファイルから default export クラスを new() して登録
      const Cls = await loadPluginClass(spec, configDir);
      registry.register(new Cls());
    } else {
      // options 付きで new()
      const Cls = await loadPluginClass(spec.file, configDir);
      registry.register(new Cls(spec.options));
    }
  }
}

/**
 * パスを解決して、プラグインファイルの default export クラスを読み込む。
 *
 * @param file - プラグインファイルのパス（configDir 基準）
 * @param configDir - config ファイルのあるディレクトリ
 * @returns プラグインクラスのコンストラクタ
 * @throws ファイル not found, default export なし, クラスでない場合
 */
async function loadPluginClass(
  file: string,
  configDir: string,
): Promise<new (...args: unknown[]) => InstanceType<never>> {
  const resolvedPath = path.resolve(configDir, file);

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
