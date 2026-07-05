import fs from "node:fs";
import path from "node:path";
import { globSync } from "node:fs";

const SCENARIO_GLOB = "**/*.{json,yaml,yml}";

export function expandScenarioPaths(inputs: string[]): string[] {
  const files: string[] = [];
  for (const input of inputs) {
    const resolved = path.resolve(input);
    const stat = fs.statSync(resolved, { throwIfNoEntry: false });

    // ディレクトリの場合はglobで展開
    if (stat?.isDirectory()) {
      const matched = globSync(SCENARIO_GLOB, { cwd: resolved });
      files.push(...matched.map((f) => path.resolve(resolved, f)));
    } else if (stat?.isFile()) {
      // ファイルが存在する場合は直接追加
      files.push(resolved);
    } else {
      // ファイルが存在しない場合はglobパターンとして処理
      files.push(...globSync(input));
    }
  }
  return [...new Set(files)];
}
