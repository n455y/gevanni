import { describe, it, expect } from "vitest";
import { parseReporterFlags, type ReporterConfig } from "./index.ts";

describe("parseReporterFlags()", () => {
  it("parses single reporter without options", () => {
    const result = parseReporterFlags(["json"]);
    expect(result).toEqual([{ name: "json", options: undefined }]);
  });

  it("parses single reporter with file option", () => {
    const result = parseReporterFlags(["json:report.json"]);
    expect(result).toEqual([{ name: "json", options: "report.json" }]);
  });

  it("parses multiple reporters", () => {
    const result = parseReporterFlags(["json:output.json", "console"]);
    expect(result).toEqual([
      { name: "json", options: "output.json" },
      { name: "console", options: undefined },
    ]);
  });

  it("parses options with colons in path", () => {
    const result = parseReporterFlags(["json:/tmp/report:custom.json"]);
    expect(result).toEqual([
      { name: "json", options: "/tmp/report:custom.json" },
    ]);
  });

  it("handles empty array as default (returns console)", () => {
    const result = parseReporterFlags([]);
    expect(result).toEqual([{ name: "console", options: undefined }]);
  });
});

describe("ReporterConfig type", () => {
  it("type checks ReporterConfig structure", () => {
    const config: ReporterConfig = { name: "json", options: "path.json" };
    expect(config.name).toBe("json");
    expect(config.options).toBe("path.json");
  });
});
