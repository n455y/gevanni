import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "path";
import { PostmanLoaderPlugin } from "./postman-loader.js";
import type { Brand } from "../../types/branded.js";

describe("PostmanLoaderPlugin", () => {
  const loader = new PostmanLoaderPlugin();

  describe("load", () => {
    it("returns empty array for non-string source", async () => {
      const result = await loader.load(42);
      expect(result).toEqual([]);
    });

    it("returns empty array for non-existent path", async () => {
      const result = await loader.load("/nonexistent/path.json");
      expect(result).toEqual([]);
    });

    it("returns empty array for invalid JSON", async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gevanni-test-"));
      const tmpFile = path.join(tmpDir, "invalid.json");
      fs.writeFileSync(tmpFile, "not json");

      const result = await loader.load(tmpFile);
      expect(result).toEqual([]);

      fs.rmSync(tmpDir, { recursive: true });
    });

    it("returns empty array for JSON without Postman structure", async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gevanni-test-"));
      const tmpFile = path.join(tmpDir, "not-postman.json");
      fs.writeFileSync(tmpFile, JSON.stringify({ foo: "bar" }));

      const result = await loader.load(tmpFile);
      expect(result).toEqual([]);

      fs.rmSync(tmpDir, { recursive: true });
    });

    it("parses a flat Postman collection into scenarios", async () => {
      const collection = {
        info: { name: "Test Collection" },
        item: [
          {
            name: "Get Users",
            request: {
              method: "GET",
              url: { raw: "https://api.example.com/users" },
              header: [{ key: "Accept", value: "application/json" }],
            },
          },
          {
            name: "Create User",
            request: {
              method: "POST",
              url: { raw: "https://api.example.com/users" },
              body: { mode: "raw", raw: '{"name":"test"}' },
            },
          },
        ],
      };

      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gevanni-test-"));
      const tmpFile = path.join(tmpDir, "collection.json");
      fs.writeFileSync(tmpFile, JSON.stringify(collection));

      const result = await loader.load(tmpFile);

      expect(result).toHaveLength(2);
      expect(result[0].name).toBe("Get Users");
      expect(result[1].name).toBe("Create User");
      expect(result[0].type).toBe("postman" as Brand<string, "ScenarioType">);
      expect(result[0].id).toBeDefined();
      expect(result[0].source).toEqual({
        items: [collection.item[0]],
      });

      fs.rmSync(tmpDir, { recursive: true });
    });

    it("flattens nested folder structure", async () => {
      const collection = {
        info: { name: "Nested" },
        item: [
          {
            name: "Folder A",
            item: [
              {
                name: "Request A1",
                request: { method: "GET", url: { raw: "https://example.com/a1" } },
              },
              {
                name: "Subfolder",
                item: [
                  {
                    name: "Request A2",
                    request: { method: "POST", url: { raw: "https://example.com/a2" } },
                  },
                ],
              },
            ],
          },
          {
            name: "Request B",
            request: { method: "DELETE", url: { raw: "https://example.com/b" } },
          },
        ],
      };

      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gevanni-test-"));
      const tmpFile = path.join(tmpDir, "nested.json");
      fs.writeFileSync(tmpFile, JSON.stringify(collection));

      const result = await loader.load(tmpFile);

      expect(result).toHaveLength(3);
      expect(result.map((s) => s.name)).toEqual([
        "Request A1",
        "Request A2",
        "Request B",
      ]);

      fs.rmSync(tmpDir, { recursive: true });
    });

    it("handles collection with empty items", async () => {
      const collection = {
        info: { name: "Empty" },
        item: [],
      };

      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gevanni-test-"));
      const tmpFile = path.join(tmpDir, "empty.json");
      fs.writeFileSync(tmpFile, JSON.stringify(collection));

      const result = await loader.load(tmpFile);
      expect(result).toEqual([]);

      fs.rmSync(tmpDir, { recursive: true });
    });
  });

  describe("init and name", () => {
    it("has correct name", () => {
      expect(loader.name).toBe("postman-loader");
    });

    it("init resolves without error", async () => {
      await expect(
        loader.init({
          commandBus: {} as any,
          eventBus: {} as any,
          config: {},
        }),
      ).resolves.toBeUndefined();
    });
  });
});
