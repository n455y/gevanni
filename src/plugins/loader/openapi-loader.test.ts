import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "path";
import type { OpenApiOperation, OpenApiScenarioSource } from "./openapi-loader.ts";
import {
  OpenApiLoaderPlugin,
  OpenApiScenarioType,
  buildChains,
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

    it("parses a simple OpenAPI 3.0 JSON spec into single-step scenarios", async () => {
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

      const src0 = result[0].source as OpenApiScenarioSource;
      expect(src0.steps).toHaveLength(1);
      expect(src0.steps[0].operation).toMatchObject({
        baseUrl: "https://api.example.com",
        method: "GET",
        path: "/users",
        parameters: [
          { name: "limit", in: "query", schema: { type: "integer" } },
        ],
      });

      const src1 = result[1].source as OpenApiScenarioSource;
      expect(src1.steps[0].operation).toMatchObject({
        method: "POST",
        requestBody: { contentType: "application/json" },
      });

      const src2 = result[2].source as OpenApiScenarioSource;
      expect(src2.steps[0].operation).toMatchObject({
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
      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps[0].operation).toMatchObject({
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
      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps[0].operation).toMatchObject({
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
      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps[0].operation.parameters).toHaveLength(1);
      expect(src.steps[0].operation.parameters[0].name).toBe("search");
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
      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps[0].operation.parameters).toHaveLength(2);
    });
  });

  describe("links", () => {
    it("extracts links from responses", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/users": {
            post: {
              operationId: "createUser",
              responses: {
                "201": {
                  links: {
                    GetUser: {
                      operationId: "getUser",
                      parameters: { id: "$response.body#/id" },
                    },
                  },
                },
              },
            },
          },
          "/users/{id}": {
            get: {
              operationId: "getUser",
              parameters: [
                { name: "id", in: "path", schema: { type: "string" } },
              ],
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      // createUser → getUser chain = 1 scenario
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("createUser");

      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps).toHaveLength(2);
      expect(src.steps[0].operation.operationId).toBe("createUser");
      expect(src.steps[0].link).toEqual({
        targetOperationId: "getUser",
        parameters: { id: "$response.body#/id" },
      });
      expect(src.steps[1].operation.operationId).toBe("getUser");
      expect(src.steps[1].link).toBeUndefined();
    });

    it("keeps standalone operations separate from chained ones", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/users": {
            post: {
              operationId: "createUser",
              responses: {
                "201": {
                  links: {
                    GetUser: {
                      operationId: "getUser",
                      parameters: { id: "$response.body#/id" },
                    },
                  },
                },
              },
            },
          },
          "/users/{id}": {
            get: {
              operationId: "getUser",
              parameters: [
                { name: "id", in: "path", schema: { type: "string" } },
              ],
            },
          },
          "/health": {
            get: {
              operationId: "healthCheck",
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      // createUser→getUser chain + standalone healthCheck
      expect(result).toHaveLength(2);
      expect(result[0].name).toBe("createUser");
      expect(result[1].name).toBe("healthCheck");

      const chainSrc = result[0].source as OpenApiScenarioSource;
      expect(chainSrc.steps).toHaveLength(2);

      const standaloneSrc = result[1].source as OpenApiScenarioSource;
      expect(standaloneSrc.steps).toHaveLength(1);
    });

    it("skips operationRef-only links", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/items": {
            post: {
              operationId: "createItem",
              responses: {
                "201": {
                  links: {
                    GetItem: {
                      operationRef: "#/paths/~1items~1{id}/get",
                      parameters: { id: "$response.body#/id" },
                    },
                  },
                },
              },
            },
          },
          "/items/{id}": {
            get: {
              operationId: "getItem",
              parameters: [
                { name: "id", in: "path", schema: { type: "string" } },
              ],
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      // No chain built since link uses operationRef, both ops are standalone
      expect(result).toHaveLength(2);
    });

    it("extracts requestBody from links", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/uuid": {
            get: {
              operationId: "getUuid",
              responses: {
                "200": {
                  links: {
                    UseUuid: {
                      operationId: "postUuid",
                      requestBody: { uuid: "$response.body#/uuid" },
                    },
                  },
                },
              },
            },
          },
          "/anything": {
            post: {
              operationId: "postUuid",
              requestBody: {
                content: {
                  "application/json": {
                    schema: { type: "object", properties: { uuid: { type: "string" } } },
                  },
                },
              },
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps).toHaveLength(2);
      expect(src.steps[0].link).toEqual({
        targetOperationId: "postUuid",
        parameters: {},
        requestBody: { uuid: "$response.body#/uuid" },
      });
    });

    it("builds separate chains for each link from a single operation", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/uuid": {
            get: {
              operationId: "getUuid",
              responses: {
                "200": {
                  links: {
                    UseUuidAsQuery: {
                      operationId: "useUuidAsQuery",
                      parameters: { uuid: "$response.body#/uuid" },
                    },
                    UseUuidInBody: {
                      operationId: "useUuidInBody",
                      requestBody: { uuid: "$response.body#/uuid" },
                    },
                  },
                },
              },
            },
          },
          "/get": {
            get: {
              operationId: "useUuidAsQuery",
              parameters: [
                { name: "uuid", in: "query", schema: { type: "string" } },
              ],
            },
          },
          "/anything": {
            post: {
              operationId: "useUuidInBody",
              requestBody: {
                content: {
                  "application/json": {
                    schema: { type: "object", properties: { uuid: { type: "string" } } },
                  },
                },
              },
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(2);

      const src0 = result[0].source as OpenApiScenarioSource;
      expect(src0.steps).toHaveLength(2);
      expect(src0.steps[0].operation.operationId).toBe("getUuid");
      expect(src0.steps[0].link?.targetOperationId).toBe("useUuidAsQuery");
      expect(src0.steps[1].operation.operationId).toBe("useUuidAsQuery");

      const src1 = result[1].source as OpenApiScenarioSource;
      expect(src1.steps).toHaveLength(2);
      expect(src1.steps[0].operation.operationId).toBe("getUuid");
      expect(src1.steps[0].link?.targetOperationId).toBe("useUuidInBody");
      expect(src1.steps[0].link?.requestBody).toEqual({
        uuid: "$response.body#/uuid",
      });
      expect(src1.steps[1].operation.operationId).toBe("useUuidInBody");
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

  describe("oneOf/anyOf request bodies", () => {
    it("generates separate scenarios for each oneOf variant", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/pets": {
            post: {
              operationId: "createPet",
              summary: "Create a pet",
              requestBody: {
                content: {
                  "application/json": {
                    schema: {
                      oneOf: [
                        {
                          type: "object",
                          properties: {
                            petType: { type: "string", enum: ["cat"] },
                            meow: { type: "string" },
                          },
                        },
                        {
                          type: "object",
                          properties: {
                            petType: { type: "string", enum: ["dog"] },
                            bark: { type: "string" },
                          },
                        },
                      ],
                    },
                  },
                },
              },
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(2);
      expect(result[0].name).toBe("createPet_variant1");
      expect(result[1].name).toBe("createPet_variant2");

      const src0 = result[0].source as OpenApiScenarioSource;
      expect(src0.steps[0].operation.requestBody?.schema).toMatchObject({
        properties: {
          petType: { type: "string", enum: ["cat"] },
          meow: { type: "string" },
        },
      });

      const src1 = result[1].source as OpenApiScenarioSource;
      expect(src1.steps[0].operation.requestBody?.schema).toMatchObject({
        properties: {
          petType: { type: "string", enum: ["dog"] },
          bark: { type: "string" },
        },
      });
    });

    it("generates separate scenarios for each anyOf variant", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/notify": {
            post: {
              operationId: "sendNotification",
              requestBody: {
                content: {
                  "application/json": {
                    schema: {
                      anyOf: [
                        {
                          type: "object",
                          properties: { email: { type: "string" } },
                        },
                        {
                          type: "object",
                          properties: { phone: { type: "string" } },
                        },
                      ],
                    },
                  },
                },
              },
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(2);
      expect(result[0].name).toBe("sendNotification_variant1");
      expect(result[1].name).toBe("sendNotification_variant2");
    });

    it("resolves allOf within request body schema", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/users": {
            post: {
              operationId: "createUser",
              requestBody: {
                content: {
                  "application/json": {
                    schema: {
                      allOf: [
                        {
                          type: "object",
                          properties: { name: { type: "string" } },
                        },
                        {
                          type: "object",
                          properties: { email: { type: "string" } },
                        },
                      ],
                    },
                  },
                },
              },
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps[0].operation.requestBody?.schema).toMatchObject({
        type: "object",
        properties: {
          name: { type: "string" },
          email: { type: "string" },
        },
      });
    });

    it("generates variants with suffix when no operationId", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/items": {
            post: {
              summary: "Create item",
              requestBody: {
                content: {
                  "application/json": {
                    schema: {
                      oneOf: [
                        { type: "string" },
                        { type: "integer" },
                      ],
                    },
                  },
                },
              },
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(2);
      expect(result[0].name).toBe("Create item (variant 1)");
      expect(result[1].name).toBe("Create item (variant 2)");
    });

    it("preserves non-oneOf operations alongside expanded ones", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/items": {
            post: {
              operationId: "createItem",
              requestBody: {
                content: {
                  "application/json": {
                    schema: {
                      oneOf: [
                        { type: "string" },
                        { type: "integer" },
                      ],
                    },
                  },
                },
              },
            },
          },
          "/health": {
            get: {
              operationId: "healthCheck",
            },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(3);
      const names = result.map((s) => s.name);
      expect(names).toContain("createItem_variant1");
      expect(names).toContain("createItem_variant2");
      expect(names).toContain("healthCheck");
    });
  });
});

describe("buildChains", () => {
  it("creates single-step chains for standalone operations", () => {
    const ops: OpenApiOperation[] = [
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/a",
        operationId: "opA",
        parameters: [],
      },
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/b",
        operationId: "opB",
        parameters: [],
      },
    ];

    const chains = buildChains(ops);
    expect(chains).toHaveLength(2);
    expect(chains[0].steps).toHaveLength(1);
    expect(chains[1].steps).toHaveLength(1);
  });

  it("detects cycles and stops", () => {
    const ops: OpenApiOperation[] = [
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/a",
        operationId: "opA",
        parameters: [],
        links: [{ targetOperationId: "opB", parameters: {} }],
      },
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/b",
        operationId: "opB",
        parameters: [],
        links: [{ targetOperationId: "opA", parameters: {} }],
      },
    ];

    const chains = buildChains(ops);
    expect(chains).toHaveLength(1);
    expect(chains[0].steps).toHaveLength(2);
  });

  it("creates separate chains for each link from one operation", () => {
    const ops: OpenApiOperation[] = [
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/root",
        operationId: "root",
        parameters: [],
        links: [
          { targetOperationId: "branchA", parameters: { id: "$response.body#/id" } },
          { targetOperationId: "branchB", parameters: {}, requestBody: { token: "$response.body#/token" } },
        ],
      },
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/a",
        operationId: "branchA",
        parameters: [],
      },
      {
        baseUrl: "http://localhost",
        method: "POST",
        path: "/b",
        operationId: "branchB",
        parameters: [],
      },
    ];

    const chains = buildChains(ops);
    expect(chains).toHaveLength(2);

    expect(chains[0].steps[0].operation.operationId).toBe("root");
    expect(chains[0].steps[0].link?.targetOperationId).toBe("branchA");
    expect(chains[0].steps[1].operation.operationId).toBe("branchA");

    expect(chains[1].steps[0].operation.operationId).toBe("root");
    expect(chains[1].steps[0].link?.targetOperationId).toBe("branchB");
    expect(chains[1].steps[0].link?.requestBody).toEqual({
      token: "$response.body#/token",
    });
    expect(chains[1].steps[1].operation.operationId).toBe("branchB");
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

  it("resolves allOf by merging properties", () => {
    expect(
      defaultValueForSchema({
        allOf: [
          { type: "object", properties: { name: { type: "string" } } },
          { type: "object", properties: { age: { type: "integer" } } },
        ],
      }),
    ).toEqual({ name: "test", age: 1 });
  });

  it("resolves oneOf by using the first variant", () => {
    expect(
      defaultValueForSchema({
        oneOf: [
          { type: "object", properties: { email: { type: "string" } } },
          { type: "object", properties: { phone: { type: "string" } } },
        ],
      }),
    ).toEqual({ email: "test" });
  });

  it("resolves anyOf by using the first variant", () => {
    expect(
      defaultValueForSchema({
        anyOf: [{ type: "integer" }, { type: "string" }],
      }),
    ).toBe(1);
  });

  it("generates defaults for object properties", () => {
    expect(
      defaultValueForSchema({
        type: "object",
        properties: {
          name: { type: "string" },
          count: { type: "integer" },
          active: { type: "boolean" },
        },
      }),
    ).toEqual({ name: "test", count: 1, active: true });
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
