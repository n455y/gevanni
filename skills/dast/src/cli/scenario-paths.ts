import fs from "node:fs";
import path from "node:path";
import { globSync } from "node:fs";

const SCENARIO_GLOB = "**/*.{json,yaml,yml}";

export function expandScenarioPaths(inputs: string[]): string[] {
  const files: string[] = [];
  for (const input of inputs) {
    const stat = fs.statSync(input, { throwIfNoEntry: false });
    if (stat?.isDirectory()) {
      const matched = globSync(SCENARIO_GLOB, { cwd: input });
      files.push(...matched.map((f) => path.resolve(input, f)));
    } else {
      files.push(...globSync(input));
    }
  }
  return [...new Set(files.map((f) => path.resolve(f)))];
}
