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
    const config = loadConfig(configPath);
    expect(config).toEqual({
      concurrency: 5,
      logLevel: "info",
      plugins: [],
      scenarioSources: [],
    });
  });

  it("returns defaults when no path is given and ./gevanni.json does not exist", () => {
    // Change cwd to tmpDir where no gevanni.json exists
    const originalCwd = process.cwd();
    process.chdir(tmpDir);
    try {
      const config = loadConfig();
      expect(config).toEqual({
        concurrency: 5,
        logLevel: "info",
        plugins: [],
        scenarioSources: [],
      });
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("reads values from gevanni.json", () => {
    const configPath = writeConfig(tmpDir, {
      concurrency: 3,
      logLevel: "debug",
      scenarioSources: ["./collections/"],
      plugins: [
        { name: "scenario:openapi", options: {} },
        { name: "reflected-xss", options: {} },
      ],
    });

    const config = loadConfig(configPath);
    expect(config.concurrency).toBe(3);
    expect(config.logLevel).toBe("debug");
    expect(config.scenarioSources).toEqual(["./collections/"]);
    expect(config.plugins).toHaveLength(2);
    expect(config.plugins[0]).toEqual({
      name: "scenario:openapi",
      options: {},
    });
  });

  it("uses defaults for missing fields in config file", () => {
    const configPath = writeConfig(tmpDir, {
      concurrency: 10,
    });

    const config = loadConfig(configPath);
    expect(config.concurrency).toBe(10);
    expect(config.logLevel).toBe("info");
    expect(config.plugins).toEqual([]);
    expect(config.scenarioSources).toEqual([]);
  });

  it("CLI overrides take precedence over file values", () => {
    const configPath = writeConfig(tmpDir, {
      concurrency: 3,
      logLevel: "debug",
      scenarioSources: ["./collections/"],
      plugins: [{ name: "proxy:http", options: {} }],
    });

    const config = loadConfig(configPath, {
      concurrency: 20,
      logLevel: "error",
    });

    expect(config.concurrency).toBe(20);
    expect(config.logLevel).toBe("error");
    // File values used for non-overridden fields
    expect(config.scenarioSources).toEqual(["./collections/"]);
    expect(config.plugins).toEqual([
      { name: "proxy:http", options: {} },
    ]);
  });

  it("CLI overrides take precedence even over defaults when no file exists", () => {
    const configPath = path.join(tmpDir, "nonexistent.json");
    const config = loadConfig(configPath, {
      concurrency: 100,
      scenarioSources: ["./custom/"],
    });

    expect(config.concurrency).toBe(100);
    expect(config.logLevel).toBe("info");
    expect(config.scenarioSources).toEqual(["./custom/"]);
    expect(config.plugins).toEqual([]);
  });

  it("handles invalid JSON gracefully", () => {
    const configPath = path.join(tmpDir, "gevanni.json");
    fs.writeFileSync(configPath, "not valid json{{{", "utf-8");

    const config = loadConfig(configPath);
    expect(config).toEqual({
      concurrency: 5,
      logLevel: "info",
      plugins: [],
      scenarioSources: [],
    });
  });

  it("handles empty JSON object", () => {
    const configPath = writeConfig(tmpDir, {});

    const config = loadConfig(configPath);
    expect(config).toEqual({
      concurrency: 5,
      logLevel: "info",
      plugins: [],
      scenarioSources: [],
    });
  });

  it("reads full example gevanni.json configuration", () => {
    const configPath = writeConfig(tmpDir, {
      concurrency: 3,
      logLevel: "debug",
      scenarioSources: ["./collections/"],
      plugins: [
        { name: "scenario:openapi", options: {} },
        { name: "proxy:http", options: {} },
        { name: "parser:query", options: {} },
        { name: "parser:json", options: {} },
        { name: "parser:form", options: {} },
        { name: "mutation:query", options: {} },
        { name: "mutation:json", options: {} },
        { name: "mutation:form", options: {} },
        { name: "reflected-xss", options: {} },
        { name: "sqli-error", options: {} },
        { name: "storage:json", options: {} },
        { name: "reporter:console", options: {} },
        { name: "reporter:json", options: {} },
      ],
    });

    const config = loadConfig(configPath);
    expect(config.concurrency).toBe(3);
    expect(config.logLevel).toBe("debug");
    expect(config.scenarioSources).toEqual(["./collections/"]);
    expect(config.plugins).toHaveLength(13);
  });
});
