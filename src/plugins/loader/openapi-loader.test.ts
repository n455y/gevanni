import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "path";
import type {
  OpenApiOperation,
} from "./openapi-loader.ts";
import {
  OpenApiLoaderPlugin,
  OpenApiScenarioType,
  defaultValueForSchema,
  isOpenApi3,
} from "./openapi-loader.ts";

describe("OpenApiLoaderPlugin", () => {
  const loader = new OpenApiLoaderPlugin();

  function writeTmpFile(content: string, ext = ".json"): string {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gevanni-test-"));
    const tmpFile = path.join(tmpDir, `spec${ext}`);
    fs.writeFileSync(tmpFile, content);
    return tmpFile;
  }

  function cleanup(filePath: string) {
    fs.rmSync(path.dirname(filePath), { recursive: true });
  }

  describe("load", () => {
    it("returns empty array for non-string source", async () => {
      expect(await loader.load(42)).toEqual([]);
    });

    it("returns empty array for non-existent path", async () => {
      expect(await loader.load("/nonexistent/path.json")).toEqual([]);
    });

    it("returns empty array for invalid content", async () => {
      const f = writeTmpFile("not json or yaml");
      expect(await loader.load(f)).toEqual([]);
      cleanup(f);
    });

    it("returns empty array for JSON that is not OpenAPI 3.x", async () => {
      const f = writeTmpFile(JSON.stringify({ foo: "bar" }));
      expect(await loader.load(f)).toEqual([]);
      cleanup(f);

      const f2 = writeTmpFile(JSON.stringify({ openapi: "2.0", paths: {} }));
      expect(await loader.load(f2)).toEqual([]);
      cleanup(f2);
    });

    it("parses a simple OpenAPI 3.0 JSON spec", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        servers: [{ url: "https://api.example.com" }],
        paths: {
          "/users": {
            get: {
              operationId: "listUsers",
              parameters: [
                {
                  name: "limit",
                  in: "query",
                  required: false,
                  schema: { type: "integer" },
                },
              ],
            },
            post: {
              operationId: "createUser",
              requestBody: {
                content: {
                  "application/json": {
                    schema: { type: "object" },
                  },
                },
              },
            },
          },
          "/users/{id}": {
            get: {
              summary: "Get user by ID",
              parameters: [
                {
                  name: "id",
                  in: "path",
                  required: true,
                  schema: { type: "integer" },
                },
              ],
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(3);
      expect(result[0].name).toBe("listUsers");
      expect(result[0].type).toBe(OpenApiScenarioType);
      expect(result[0].source).toMatchObject({
        baseUrl: "https://api.example.com",
        method: "GET",
        path: "/users",
        parameters: [
          { name: "limit", in: "query", schema: { type: "integer" } },
        ],
      });

      expect(result[1].name).toBe("createUser");
      expect(result[1].source).toMatchObject({
        method: "POST",
        requestBody: { contentType: "application/json" },
      });

      expect(result[2].name).toBe("Get user by ID");
      expect(result[2].source).toMatchObject({
        path: "/users/{id}",
        parameters: [{ name: "id", in: "path" }],
      });
    });

    it("parses an OpenAPI 3.x YAML spec", async () => {
      const yamlContent = `
openapi: "3.1.0"
info:
  title: Petstore
  version: "1.0.0"
servers:
  - url: https://petstore.example.com
paths:
  /pets:
    get:
      operationId: listPets
      parameters:
        - name: type
          in: query
          schema:
            type: string
      `;
      const f = writeTmpFile(yamlContent, ".yaml");
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("listPets");
      expect(result[0].source).toMatchObject({
        baseUrl: "https://petstore.example.com",
        method: "GET",
        path: "/pets",
      });
    });

    it("defaults baseUrl to http://localhost when no servers", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: { "/health": { get: { operationId: "health" } } },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      expect(result[0].source).toMatchObject({
        baseUrl: "http://localhost",
      });
    });

    it("skips $ref parameters", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/items": {
            get: {
              operationId: "listItems",
              parameters: [
                { $ref: "#/components/parameters/PageParam" },
                {
                  name: "search",
                  in: "query",
                  schema: { type: "string" },
                },
              ],
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      const source = result[0].source as OpenApiOperation;
      expect(source.parameters).toHaveLength(1);
      expect(source.parameters[0].name).toBe("search");
    });

    it("merges path-level and operation-level parameters", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/items/{id}": {
            parameters: [
              {
                name: "id",
                in: "path",
                required: true,
                schema: { type: "string" },
              },
            ],
            get: {
              operationId: "getItem",
              parameters: [
                {
                  name: "fields",
                  in: "query",
                  schema: { type: "string" },
                },
              ],
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      const source = result[0].source as OpenApiOperation;
      expect(source.parameters).toHaveLength(2);
    });
  });

  describe("init and name", () => {
    it("has correct name", () => {
      expect(loader.name).toBe("openapi-loader");
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

describe("defaultValueForSchema", () => {
  it("returns example when provided", () => {
    expect(defaultValueForSchema({ type: "string" }, "hello")).toBe("hello");
  });

  it("returns defaults for each type", () => {
    expect(defaultValueForSchema({ type: "string" })).toBe("test");
    expect(defaultValueForSchema({ type: "integer" })).toBe(1);
    expect(defaultValueForSchema({ type: "number" })).toBe(1);
    expect(defaultValueForSchema({ type: "boolean" })).toBe(true);
    expect(defaultValueForSchema({ type: "array" })).toEqual([]);
    expect(defaultValueForSchema({ type: "object" })).toEqual({});
  });

  it("returns 'test' when no schema", () => {
    expect(defaultValueForSchema(undefined)).toBe("test");
  });
});

describe("isOpenApi3", () => {
  it("accepts valid OpenAPI 3.x docs", () => {
    expect(isOpenApi3({ openapi: "3.0.0" })).toBe(true);
    expect(isOpenApi3({ openapi: "3.1.0" })).toBe(true);
  });

  it("rejects non-OpenAPI docs", () => {
    expect(isOpenApi3(null)).toBe(false);
    expect(isOpenApi3({})).toBe(false);
    expect(isOpenApi3({ openapi: "2.0" })).toBe(false);
    expect(isOpenApi3({ swagger: "2.0" })).toBe(false);
  });
});
