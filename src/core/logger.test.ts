import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createLogger } from "./logger.js";

describe("createLogger", () => {
  let output: string;

  beforeEach(() => {
    output = "";
    vi.spyOn(process.stderr, "write").mockImplementation((str: string | Uint8Array) => {
      if (typeof str === "string") {
        output += str;
      }
      return true;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("logs messages at or above configured level", () => {
    const logger = createLogger("warn");

    logger.debug("skip");
    logger.info("skip");
    logger.warn("visible-warn");
    logger.error("visible-error");

    expect(output).not.toContain("[DEBUG]");
    expect(output).not.toContain("[INFO]");
    expect(output).toContain("[WARN] visible-warn\n");
    expect(output).toContain("[ERROR] visible-error\n");
  });

  it("suppresses messages below configured level", () => {
    const logger = createLogger("error");

    logger.debug("skip");
    logger.info("skip");
    logger.warn("skip");

    expect(output).toBe("");
  });

  it("defaults to info level", () => {
    const logger = createLogger();

    logger.debug("skip");
    logger.info("visible");
    logger.warn("visible");
    logger.error("visible");

    expect(output).not.toContain("[DEBUG]");
    expect(output).toContain("[INFO] visible\n");
    expect(output).toContain("[WARN] visible\n");
    expect(output).toContain("[ERROR] visible\n");
  });
});
