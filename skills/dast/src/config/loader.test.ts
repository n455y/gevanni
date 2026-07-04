import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { loadConfig } from "./loader.ts";

describe("loadConfig", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gevanni-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function writeConfig(dir: string, data: unknown): string {
    const filePath = path.join(dir, "gevanni.json");
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
    return filePath;
  }

  it("returns defaults when config file does not exist", () => {
    const configPath = path.join(tmpDir, "nonexistent.json");
    const { config } = loadConfig(configPath);
    expect(config).toEqual({
      concurrency: 5,
      logLevel: "info",
      plugins: [],
      scenarios: [],
    });
  });

  it("returns defaults when no path is given and ./gevanni.json does not exist", () => {
    // Change cwd to tmpDir where no gevanni.json exists
    const originalCwd = process.cwd();
    process.chdir(tmpDir);
    try {
      const { config } = loadConfig();
      expect(config).toEqual({
        concurrency: 5,
        logLevel: "info",
        plugins: [],
        scenarios: [],
      });
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("reads values from gevanni.json", () => {
    const configPath = writeConfig(tmpDir, {
      concurrency: 3,
      logLevel: "debug",
      scenarios: [
        { type: "openapi", file: "./spec.yaml" },
      ],
      plugins: [
        ":builtin:",
      ],
    });

    const { config } = loadConfig(configPath);
    expect(config.concurrency).toBe(3);
    expect(config.logLevel).toBe("debug");
    expect(config.scenarios).toEqual([
      { type: "openapi", file: "./spec.yaml" },
    ]);
    expect(config.plugins).toEqual([
      ":builtin:",
    ]);
  });

  it("uses defaults for missing fields in config file", () => {
    const configPath = writeConfig(tmpDir, {
      concurrency: 10,
    });

    const { config } = loadConfig(configPath);
    expect(config.concurrency).toBe(10);
    expect(config.logLevel).toBe("info");
    expect(config.plugins).toEqual([]);
    expect(config.scenarios).toEqual([]);
  });

  it("CLI overrides take precedence over file values", () => {
    const configPath = writeConfig(tmpDir, {
      concurrency: 3,
      logLevel: "debug",
      scenarios: [
        { type: "openapi", file: "./spec.yaml" },
      ],
      plugins: [
        "./.gevanni/plugins/custom.ts",
      ],
    });

    const { config } = loadConfig(configPath, {
      concurrency: 20,
      logLevel: "error",
    });

    expect(config.concurrency).toBe(20);
    expect(config.logLevel).toBe("error");
    // File values used for non-overridden fields
    expect(config.scenarios).toEqual([
      { type: "openapi", file: "./spec.yaml" },
    ]);
    expect(config.plugins).toEqual([
      "./.gevanni/plugins/custom.ts",
    ]);
  });

  it("CLI overrides take precedence even over defaults when no file exists", () => {
    const configPath = path.join(tmpDir, "nonexistent.json");
    const { config } = loadConfig(configPath, {
      concurrency: 100,
    });

    expect(config.concurrency).toBe(100);
    expect(config.logLevel).toBe("info");
    expect(config.scenarios).toEqual([]);
    expect(config.plugins).toEqual([]);
  });

  it("handles invalid JSON gracefully", () => {
    const configPath = path.join(tmpDir, "gevanni.json");
    fs.writeFileSync(configPath, "not valid json{{{", "utf-8");

    const { config } = loadConfig(configPath);
    expect(config).toEqual({
      concurrency: 5,
      logLevel: "info",
      plugins: [],
      scenarios: [],
    });
  });

  it("handles empty JSON object", () => {
    const configPath = writeConfig(tmpDir, {});

    const { config } = loadConfig(configPath);
    expect(config).toEqual({
      concurrency: 5,
      logLevel: "info",
      plugins: [],
      scenarios: [],
    });
  });

  it("reads full example gevanni.json configuration", () => {
    const configPath = writeConfig(tmpDir, {
      concurrency: 3,
      logLevel: "debug",
      scenarios: [
        { type: "openapi", file: "./spec.yaml" },
      ],
      plugins: [
        ":builtin:",
        "./.gevanni/plugins/custom.ts",
        { file: "./.gevanni/plugins/custom-with-opts.ts", options: { key: "value" } },
      ],
    });

    const { config } = loadConfig(configPath);
    expect(config.concurrency).toBe(3);
    expect(config.logLevel).toBe("debug");
    expect(config.scenarios).toEqual([
      { type: "openapi", file: "./spec.yaml" },
    ]);
    expect(config.plugins).toHaveLength(3);
  });
});
