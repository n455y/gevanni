import fs from "node:fs";
import path from "node:path";
import { registerAllBuiltinPlugins, registerBuiltinPlugin } from "../builtin.ts";
import type { PluginRegistry } from "../core/plugin.ts";
import type { PluginSpec } from "./loader.ts";

/**
 * Resolve an array of PluginSpecs and register them in the PluginRegistry.
 * Plugins with the same name are overwritten (last wins, per Map.set semantics).
 *
 * @param specs - PluginSpec array
 * @param registry - Plugin registry
 * @param searchDirs - Base directories to search for plugin files (in priority order)
 */
export async function loadPlugins(
  specs: PluginSpec[],
  registry: PluginRegistry,
  searchDirs: string[],
): Promise<void> {
  for (const spec of specs) {
    if (spec === ":builtin:") {
      // Register all builtin plugins
      registerAllBuiltinPlugins(registry);
    } else if (typeof spec === "string") {
      // Load default-export class from file and instantiate
      const Cls = await loadPluginClass(spec, searchDirs);
      registry.register(new Cls());
    } else if ("name" in spec) {
      // Register builtin plugin by name with options override
      registerBuiltinPlugin(registry, spec.name, spec.options);
    } else {
      // File + options
      const Cls = await loadPluginClass(spec.file, searchDirs);
      registry.register(new Cls(spec.options ?? {}));
    }
  }
}

/**
 * Resolve the absolute path of a plugin file from multiple search directories.
 * Returns the first match found, or null if not found.
 *
 * @param file - Relative path to the plugin file
 * @param searchDirs - List of base directories to search (in priority order)
 * @returns Resolved absolute path, or null
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
 * Search multiple directories for a plugin file and load its default-export class.
 *
 * @param file - Plugin file path (relative to searchDirs)
 * @param searchDirs - List of base directories to search (in priority order)
 * @returns The plugin class constructor
 * @throws If file not found, has no default export, or is not a class
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

  // Check for default export
  if (mod === null || typeof mod !== "object" || !("default" in mod)) {
    throw new Error(`Plugin file "${resolvedPath}" has no default export`);
  }
  const Cls = (mod as { default: unknown }).default;

  // Check that it's a class (constructor)
  if (typeof Cls !== "function" || Cls.toString().startsWith("class") === false) {
    throw new Error(
      `Default export of "${resolvedPath}" is not a class (constructor)`,
    );
  }

  return Cls as new (...args: unknown[]) => InstanceType<never>;
}

/**
 * Auto-discover .ts / .js files from plugins/autoload/ in the given directories,
 * returning them as a PluginSpec array.
 * Directories where plugins/autoload/ doesn't exist are silently skipped.
 *
 * Returned paths are absolute. Duplicates are removed, and results are sorted by filename.
 *
 * @param searchDirs - Parent directories to search (e.g., configDir, cwd/.gevanni)
 * @returns Array of absolute-path PluginSpecs for discovered plugin files
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
  // Sort by filename (deterministic order)
  results.sort((a, b) => path.basename(a).localeCompare(path.basename(b)));
  return results;
}
