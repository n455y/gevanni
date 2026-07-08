import fs from "node:fs";
import path from "node:path";
import { globSync } from "node:fs";

const SCENARIO_GLOB = "**/*.{json,yaml,yml}";

export function expandScenarioPaths(inputs: string[]): string[] {
  const files: string[] = [];
  for (const input of inputs) {
    const resolved = path.resolve(input);
    const stat = fs.statSync(resolved, { throwIfNoEntry: false });

    // Expand directories using glob
    if (stat?.isDirectory()) {
      const matched = globSync(SCENARIO_GLOB, { cwd: resolved });
      files.push(...matched.map((f) => path.resolve(resolved, f)));
    } else if (stat?.isFile()) {
      // File exists, add directly
      files.push(resolved);
    } else {
      // File doesn't exist, treat as glob pattern
      files.push(...globSync(input));
    }
  }
  return [...new Set(files)];
}
