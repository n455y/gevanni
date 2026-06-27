import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { expandScenarioPaths } from "./scenario-paths.ts";

describe("expandScenarioPaths", () => {
  it("expands a glob pattern into matched files", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "gevanni-"));
    writeFileSync(path.join(dir, "a.openapi.yaml"), "openapi: 3.0.0");
    writeFileSync(path.join(dir, "b.openapi.json"), '{"openapi":"3.0.0"}');
    const result = expandScenarioPaths([path.join(dir, "*.openapi.{yaml,json}")]);
    expect(result.length).toBe(2);
  });

  it("expands a directory recursively for json/yaml/yml", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "gevanni-"));
    const sub = path.join(dir, "sub");
    mkdirSync(sub);
    writeFileSync(path.join(dir, "a.yaml"), "x: 1");
    writeFileSync(path.join(sub, "b.yml"), "y: 2");
    writeFileSync(path.join(dir, "ignore.txt"), "nope");
    const result = expandScenarioPaths([dir]);
    expect(result.some((f: string) => f.endsWith("a.yaml"))).toBe(true);
    expect(result.some((f: string) => f.endsWith("b.yml"))).toBe(true);
    expect(result.some((f: string) => f.endsWith("ignore.txt"))).toBe(false);
  });

  it("returns a single existing file as one absolute path", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "gevanni-"));
    const file = path.join(dir, "single.yaml");
    writeFileSync(file, "x: 1");
    const result = expandScenarioPaths([file]);
    expect(result).toEqual([path.resolve(file)]);
  });

  it("deduplicates overlapping inputs", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "gevanni-"));
    const file = path.join(dir, "dup.yaml");
    writeFileSync(file, "x: 1");
    const result = expandScenarioPaths([file, file]);
    expect(result).toEqual([path.resolve(file)]);
  });
});
