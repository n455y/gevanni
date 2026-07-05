import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "path";
import type { OpenApiOperation, OpenApiScenarioSource } from "./loader.ts";
import {
  loadOpenApiScenarios,
  OpenApiScenarioType,
  buildScenariosFromExtension,
  defaultValueForSchema,
  isOpenApi3,
} from "./loader.ts";
import OpenApiLoaderPlugin from "./loader.ts";

describe("OpenApiLoader", () => {
  const loader = { load: loadOpenApiScenarios };

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
              operationId: "getUserById",
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
        "x-gevanni-scenarios": [
          { id: "listUsers", steps: ["listUsers"] },
          { id: "createUser", steps: ["createUser"] },
          { id: "getUserById", steps: ["getUserById"] },
        ],
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
x-gevanni-scenarios:
  - id: listPets
    steps:
      - listPets
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
        "x-gevanni-scenarios": [{ id: "health", steps: ["health"] }],
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
        "x-gevanni-scenarios": [{ id: "listItems", steps: ["listItems"] }],
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
        "x-gevanni-scenarios": [{ id: "getItem", steps: ["getItem"] }],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps[0].operation.parameters).toHaveLength(2);
    });
  });

  describe("x-gevanni-scenarios", () => {
    it("returns empty when no x-gevanni-scenarios extension", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/users": {
            get: { operationId: "listUsers" },
          },
        },
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(0);
    });

    it("parses x-gevanni-scenarios with steps", async () => {
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
        "x-gevanni-scenarios": [
          {
            id: "userFlow",
            steps: ["createUser", "getUser"],
          },
        ],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("userFlow");

      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps).toHaveLength(2);
      expect(src.steps[0].operation.operationId).toBe("createUser");
      expect(src.steps[0].link).toEqual({
        targetOperationId: "getUser",
        parameters: { id: "$response.body#/id" },
      });
      expect(src.steps[1].operation.operationId).toBe("getUser");
      expect(src.steps[1].link).toBeUndefined();
      expect(src.secondOrders).toBeUndefined();
    });

    it("parses x-gevanni-scenarios with scenario-level secondOrders", async () => {
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
        "x-gevanni-scenarios": [
          {
            id: "uuidFlow",
            steps: ["getUuid", "useUuidInBody"],
            secondOrders: [
              { steps: ["getUuid", "useUuidAsQuery"] },
              { steps: ["getUuid", "useUuidInBody"] },
            ],
          },
        ],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("uuidFlow");

      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps).toHaveLength(2);
      expect(src.steps[0].operation.operationId).toBe("getUuid");
      expect(src.steps[0].link?.targetOperationId).toBe("useUuidInBody");
      expect(src.steps[0].link?.requestBody).toEqual({
        uuid: "$response.body#/uuid",
      });

      expect(src.steps[1].operation.operationId).toBe("useUuidInBody");
      expect(src.secondOrders).toHaveLength(2);
      expect(src.secondOrders![0].steps).toHaveLength(2);
      expect(src.secondOrders![0].steps[0].operation.operationId).toBe("getUuid");
      expect(src.secondOrders![0].steps[0].link?.targetOperationId).toBe("useUuidAsQuery");
      expect(src.secondOrders![0].steps[1].operation.operationId).toBe("useUuidAsQuery");

      expect(src.secondOrders![1].steps).toHaveLength(2);
      expect(src.secondOrders![1].steps[0].operation.operationId).toBe("getUuid");
      expect(src.secondOrders![1].steps[0].link?.targetOperationId).toBe("useUuidInBody");
    });

    it("skips unknown operationIds in steps", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/health": {
            get: { operationId: "healthCheck" },
          },
        },
        "x-gevanni-scenarios": [
          {
            id: "goodFlow",
            steps: ["healthCheck"],
          },
          {
            id: "badFlow",
            steps: ["nonExistent"],
          },
        ],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("goodFlow");
    });

    it("uses operationId as name when scenario id is missing", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/health": {
            get: { operationId: "healthCheck" },
          },
        },
        "x-gevanni-scenarios": [
          { steps: ["healthCheck"] },
        ],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("healthCheck");
    });
  });

  describe("oneOf request bodies", () => {
    it("selects oneOf variant using match", async () => {
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
        "x-gevanni-scenarios": [
          { id: "createPet_cat", steps: [{ id: "createPet", match: { petType: "cat" } }] },
          { id: "createPet_dog", steps: [{ id: "createPet", match: { petType: "dog" } }] },
        ],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(2);
      expect(result[0].name).toBe("createPet_cat");
      expect(result[1].name).toBe("createPet_dog");

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
        "x-gevanni-scenarios": [
          { id: "createUser", steps: ["createUser"] },
        ],
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

    it("selects variant by index when no discriminant", async () => {
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
        },
        "x-gevanni-scenarios": [
          { id: "stringVariant", steps: [{ id: "createItem", match: 0 }] },
          { id: "intVariant", steps: [{ id: "createItem", match: 1 }] },
        ],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(2);

      const src0 = result[0].source as OpenApiScenarioSource;
      expect(src0.steps[0].operation.requestBody?.schema).toMatchObject({ type: "string" });

      const src1 = result[1].source as OpenApiScenarioSource;
      expect(src1.steps[0].operation.requestBody?.schema).toMatchObject({ type: "integer" });
    });

    it("preserves non-oneOf operations alongside ones with variants", async () => {
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
        "x-gevanni-scenarios": [
          { id: "createItem_v1", steps: [{ id: "createItem", match: 0 }] },
          { id: "createItem_v2", steps: [{ id: "createItem", match: 1 }] },
          { id: "healthCheck", steps: ["healthCheck"] },
        ],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(3);
      const names = result.map((s) => s.name);
      expect(names).toContain("createItem_v1");
      expect(names).toContain("createItem_v2");
      expect(names).toContain("healthCheck");
    });
  });

  describe("$ref resolution", () => {
    it("resolves $ref parameters from components", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/items/{id}": {
            get: {
              operationId: "getItem",
              parameters: [
                { $ref: "#/components/parameters/ItemId" },
              ],
            },
          },
        },
        components: {
          parameters: {
            ItemId: {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "integer" },
            },
          },
        },
        "x-gevanni-scenarios": [{ id: "getItem", steps: ["getItem"] }],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps[0].operation.parameters).toEqual([
        {
          name: "id",
          in: "path",
          required: true,
          schema: { type: "integer" },
          example: undefined,
        },
      ]);
    });

    it("resolves $ref request body schema from components", async () => {
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
                    schema: { $ref: "#/components/schemas/User" },
                  },
                },
              },
            },
          },
        },
        components: {
          schemas: {
            User: {
              type: "object",
              properties: {
                name: { type: "string" },
                email: { type: "string" },
              },
            },
          },
        },
        "x-gevanni-scenarios": [{ id: "createUser", steps: ["createUser"] }],
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

    it("resolves $ref in requestBody itself", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/items": {
            post: {
              operationId: "createItem",
              requestBody: {
                $ref: "#/components/requestBodies/ItemBody",
              },
            },
          },
        },
        components: {
          requestBodies: {
            ItemBody: {
              content: {
                "application/json": {
                  schema: { type: "object", properties: { name: { type: "string" } } },
                },
              },
            },
          },
        },
        "x-gevanni-scenarios": [{ id: "createItem", steps: ["createItem"] }],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps[0].operation.requestBody?.schema).toMatchObject({
        type: "object",
        properties: { name: { type: "string" } },
      });
    });

    it("resolves $ref inside oneOf variants", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/pets": {
            post: {
              operationId: "createPet",
              requestBody: {
                content: {
                  "application/json": {
                    schema: {
                      oneOf: [
                        { $ref: "#/components/schemas/Cat" },
                        { $ref: "#/components/schemas/Dog" },
                      ],
                    },
                  },
                },
              },
            },
          },
        },
        components: {
          schemas: {
            Cat: {
              type: "object",
              properties: {
                petType: { type: "string", enum: ["cat"] },
                meow: { type: "string" },
              },
            },
            Dog: {
              type: "object",
              properties: {
                petType: { type: "string", enum: ["dog"] },
                bark: { type: "string" },
              },
            },
          },
        },
        "x-gevanni-scenarios": [
          { id: "createPet_cat", steps: [{ id: "createPet", match: { petType: "cat" } }] },
          { id: "createPet_dog", steps: [{ id: "createPet", match: { petType: "dog" } }] },
        ],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(2);
      expect(result[0].name).toBe("createPet_cat");
      expect(result[1].name).toBe("createPet_dog");

      const src0 = result[0].source as OpenApiScenarioSource;
      expect(src0.steps[0].operation.requestBody?.schema).toMatchObject({
        properties: {
          petType: { type: "string", enum: ["cat"] },
          meow: { type: "string" },
        },
      });
    });

    it("skips step when match finds no variant", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/pets": {
            post: {
              operationId: "createPet",
              requestBody: {
                content: {
                  "application/json": {
                    schema: {
                      oneOf: [
                        {
                          type: "object",
                          properties: { petType: { type: "string", enum: ["cat"] } },
                        },
                      ],
                    },
                  },
                },
              },
            },
          },
        },
        "x-gevanni-scenarios": [
          { id: "createDog", steps: [{ id: "createPet", match: { petType: "dog" } }] },
        ],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      // match did not resolve → uses default first variant (no error thrown)
      expect(result).toHaveLength(1);
    });

    it("resolves nested oneOf with nested match", async () => {
      const spec = {
        openapi: "3.0.0",
        info: { title: "Test", version: "1.0.0" },
        paths: {
          "/thing": {
            post: {
              operationId: "createThing",
              requestBody: {
                content: {
                  "application/json": {
                    schema: {
                      oneOf: [
                        {
                          type: "object",
                          properties: {
                            type: { type: "string", const: "vehicle" },
                            detail: {
                              oneOf: [
                                {
                                  type: "object",
                                  properties: {
                                    kind: { type: "string", const: "car" },
                                    doors: { type: "integer" },
                                  },
                                },
                                {
                                  type: "object",
                                  properties: {
                                    kind: { type: "string", const: "bike" },
                                    wheels: { type: "integer" },
                                  },
                                },
                              ],
                            },
                          },
                        },
                        {
                          type: "object",
                          properties: {
                            type: { type: "string", const: "building" },
                            floors: { type: "integer" },
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
        "x-gevanni-scenarios": [
          {
            id: "createVehicleCar",
            steps: [{ id: "createThing", match: { type: "vehicle", detail: { kind: "car" } } }],
          },
        ],
      };

      const f = writeTmpFile(JSON.stringify(spec));
      const result = await loader.load(f);
      cleanup(f);

      expect(result).toHaveLength(1);
      const src = result[0].source as OpenApiScenarioSource;
      expect(src.steps[0].operation.requestBody?.schema).toMatchObject({
        properties: {
          type: { type: "string", const: "vehicle" },
        },
      });
    });
  });
});

describe("buildScenariosFromExtension", () => {
  it("returns empty for doc without x-gevanni-scenarios", () => {
    const ops: OpenApiOperation[] = [
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/a",
        operationId: "opA",
        parameters: [],
      },
    ];

    const sources = buildScenariosFromExtension({}, ops);
    expect(sources).toHaveLength(0);
  });

  it("builds scenario source from x-gevanni-scenarios", () => {
    const ops: OpenApiOperation[] = [
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/a",
        operationId: "opA",
        parameters: [],
        links: [{ targetOperationId: "opB", parameters: { id: "$response.body#/id" } }],
      },
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/b",
        operationId: "opB",
        parameters: [],
      },
    ];

    const doc = {
      "x-gevanni-scenarios": [
        { id: "chain1", steps: ["opA", "opB"] },
      ],
    };

    const sources = buildScenariosFromExtension(doc, ops);
    expect(sources).toHaveLength(1);
    expect(sources[0].steps).toHaveLength(2);
    expect(sources[0].steps[0].operation.operationId).toBe("opA");
    expect(sources[0].steps[0].link?.targetOperationId).toBe("opB");
    expect(sources[0].steps[1].operation.operationId).toBe("opB");
    expect(sources[0].steps[1].link).toBeUndefined();
    expect(sources[0].secondOrders).toBeUndefined();
  });

  it("expands scenario id references in steps", () => {
    const ops: OpenApiOperation[] = [
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/uuid",
        operationId: "getUuid",
        parameters: [],
        links: [
          { targetOperationId: "useUuidInBody", parameters: { uuid: "$response.body#/uuid" } },
          { targetOperationId: "useUuidAsQuery", parameters: { uuid: "$response.body#/uuid" } },
        ],
      },
      {
        baseUrl: "http://localhost",
        method: "POST",
        path: "/anything",
        operationId: "useUuidInBody",
        parameters: [],
      },
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/get",
        operationId: "useUuidAsQuery",
        parameters: [],
      },
    ];

    const doc = {
      "x-gevanni-scenarios": [
        { id: "getUuidPart", steps: ["getUuid"] },
        { id: "uuidInBody", steps: ["getUuidPart", "useUuidInBody"] },
        { id: "uuidAsQuery", steps: ["getUuidPart", "useUuidAsQuery"] },
      ],
    };

    const sources = buildScenariosFromExtension(doc, ops);
    expect(sources).toHaveLength(3);

    // First scenario (the part) stays as-is
    expect(sources[0].steps).toHaveLength(1);
    expect(sources[0].steps[0].operation.operationId).toBe("getUuid");

    // Second scenario expands getUuidPart → [getUuid]
    expect(sources[1].steps).toHaveLength(2);
    expect(sources[1].steps[0].operation.operationId).toBe("getUuid");
    expect(sources[1].steps[0].link?.targetOperationId).toBe("useUuidInBody");
    expect(sources[1].steps[1].operation.operationId).toBe("useUuidInBody");

    // Third scenario also expands getUuidPart → [getUuid]
    expect(sources[2].steps).toHaveLength(2);
    expect(sources[2].steps[0].operation.operationId).toBe("getUuid");
    expect(sources[2].steps[0].link?.targetOperationId).toBe("useUuidAsQuery");
    expect(sources[2].steps[1].operation.operationId).toBe("useUuidAsQuery");
  });

  it("expands nested scenario id references", () => {
    const ops: OpenApiOperation[] = [
      {
        baseUrl: "http://localhost",
        method: "POST",
        path: "/users",
        operationId: "createUser",
        parameters: [],
        links: [{ targetOperationId: "verifyEmail", parameters: { id: "$response.body#/id" } }],
      },
      {
        baseUrl: "http://localhost",
        method: "POST",
        path: "/verify",
        operationId: "verifyEmail",
        parameters: [],
        links: [{ targetOperationId: "login", parameters: { id: "$response.body#/id" } }],
      },
      {
        baseUrl: "http://localhost",
        method: "POST",
        path: "/login",
        operationId: "login",
        parameters: [],
      },
    ];

    const doc = {
      "x-gevanni-scenarios": [
        { id: "createAndVerify", steps: ["createUser", "verifyEmail"] },
        { id: "fullFlow", steps: ["createAndVerify", "login"] },
      ],
    };

    const sources = buildScenariosFromExtension(doc, ops);
    expect(sources).toHaveLength(2);

    // fullFlow expands createAndVerify → [createUser, verifyEmail] + [login]
    expect(sources[1].steps).toHaveLength(3);
    expect(sources[1].steps[0].operation.operationId).toBe("createUser");
    expect(sources[1].steps[1].operation.operationId).toBe("verifyEmail");
    expect(sources[1].steps[2].operation.operationId).toBe("login");
  });

  it("prefers operationId over scenario id when names conflict", () => {
    const ops: OpenApiOperation[] = [
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/shared",
        operationId: "shared",
        parameters: [],
      },
      {
        baseUrl: "http://localhost",
        method: "POST",
        path: "/next",
        operationId: "next",
        parameters: [],
      },
    ];

    const doc = {
      "x-gevanni-scenarios": [
        { id: "shared", steps: ["shared"] },
        { id: "flow", steps: ["shared", "next"] },
      ],
    };

    const sources = buildScenariosFromExtension(doc, ops);
    // "shared" in flow matches an operationId, so it's NOT expanded
    expect(sources[1].steps).toHaveLength(2);
    expect(sources[1].steps[0].operation.operationId).toBe("shared");
    expect(sources[1].steps[1].operation.operationId).toBe("next");
  });

  it("resolves scenario-level secondOrders with scenario id references", () => {
    const ops: OpenApiOperation[] = [
      {
        baseUrl: "http://localhost",
        method: "GET",
        path: "/root",
        operationId: "root",
        parameters: [],
        links: [
          { targetOperationId: "branchA", parameters: {} },
          { targetOperationId: "branchB", parameters: {} },
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

    const doc = {
      "x-gevanni-scenarios": [
        { id: "rootPart", steps: ["root"] },
        {
          id: "mainFlow",
          steps: ["rootPart", "branchA"],
          secondOrders: [{ steps: ["rootPart", "branchB"] }],
        },
      ],
    };

    const sources = buildScenariosFromExtension(doc, ops);
    expect(sources).toHaveLength(2);

    // mainFlow has scenario-level secondOrders, rootPart expanded
    const src = sources[1];
    expect(src.steps).toHaveLength(2);
    expect(src.steps[0].operation.operationId).toBe("root");
    expect(src.steps[1].operation.operationId).toBe("branchA");

    const so = src.secondOrders;
    expect(so).toHaveLength(1);
    expect(so![0].steps).toHaveLength(2);
    expect(so![0].steps[0].operation.operationId).toBe("root");
    expect(so![0].steps[0].link?.targetOperationId).toBe("branchB");
    expect(so![0].steps[1].operation.operationId).toBe("branchB");
  });

  it("builds scenario with scenario-level secondOrders", () => {
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

    const doc = {
      "x-gevanni-scenarios": [
        {
          id: "mainFlow",
          steps: ["root", "branchA"],
          secondOrders: [
            { steps: ["root", "branchB"] },
          ],
        },
      ],
    };

    const sources = buildScenariosFromExtension(doc, ops);
    expect(sources).toHaveLength(1);

    expect(sources[0].steps[0].operation.operationId).toBe("root");
    expect(sources[0].steps[0].link?.targetOperationId).toBe("branchA");
    expect(sources[0].steps[1].operation.operationId).toBe("branchA");

    const so = sources[0].secondOrders;
    expect(so).toHaveLength(1);
    expect(so![0].steps[0].operation.operationId).toBe("root");
    expect(so![0].steps[0].link?.targetOperationId).toBe("branchB");
    expect(so![0].steps[0].link?.requestBody).toEqual({
      token: "$response.body#/token",
    });
    expect(so![0].steps[1].operation.operationId).toBe("branchB");
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

  it("uses default value when provided", () => {
    expect(defaultValueForSchema({ type: "string", default: "hello" })).toBe("hello");
    expect(defaultValueForSchema({ type: "integer", default: 42 })).toBe(42);
    expect(defaultValueForSchema({ type: "boolean", default: false })).toBe(false);
  });

  it("prefers example over default", () => {
    expect(
      defaultValueForSchema({ type: "string", default: "fallback" }, "override"),
    ).toBe("override");
  });

  it("uses first enum value", () => {
    expect(
      defaultValueForSchema({ type: "string", enum: ["active", "inactive"] }),
    ).toBe("active");
  });

  it("prefers example over enum", () => {
    expect(
      defaultValueForSchema({ type: "string", enum: ["a", "b"] }, "c"),
    ).toBe("c");
  });

  it("prefers default over enum", () => {
    expect(
      defaultValueForSchema({ type: "string", enum: ["a", "b"], default: "b" }),
    ).toBe("b");
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

describe("scannable", () => {
  function writeTmpFile(content: string, ext = ".json"): string {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gevanni-test-"));
    const tmpFile = path.join(tmpDir, `spec${ext}`);
    fs.writeFileSync(tmpFile, content);
    return tmpFile;
  }

  function cleanup(filePath: string) {
    fs.rmSync(path.dirname(filePath), { recursive: true });
  }

  it("defaults scannable to true", async () => {
    const spec = {
      openapi: "3.0.0",
      info: { title: "Test", version: "1.0.0" },
      paths: { "/a": { get: { operationId: "opA" } } },
      "x-gevanni-scenarios": [{ id: "s1", steps: ["opA"] }],
    };

    const f = writeTmpFile(JSON.stringify(spec));
    const result = await loadOpenApiScenarios(f);
    cleanup(f);

    const src = result[0].source as OpenApiScenarioSource;
    expect(src.scannable).toBe(true);
  });

  it("excludes scenario when scannable is false", async () => {
    const spec = {
      openapi: "3.0.0",
      info: { title: "Test", version: "1.0.0" },
      paths: { "/a": { get: { operationId: "opA" } } },
      "x-gevanni-scenarios": [
        { id: "s1", steps: ["opA"], scannable: false },
      ],
    };

    const f = writeTmpFile(JSON.stringify(spec));
    const result = await loadOpenApiScenarios(f);
    cleanup(f);

    expect(result).toHaveLength(0);
  });
});

describe("OpenApiLoaderPlugin", () => {
  it("has the scenario-loader:openapi name", () => {
    const plugin = new OpenApiLoaderPlugin();
    expect(plugin.name).toBe("scenario-loader:openapi");
  });

  it("init is a no-op that resolves", async () => {
    const plugin = new OpenApiLoaderPlugin();
    await expect(plugin.init({} as never)).resolves.toBeUndefined();
  });

  it("delegates loadScenarios to loadOpenApiScenarios: non-string source → []", async () => {
    const plugin = new OpenApiLoaderPlugin();
    expect(await plugin.loadScenarios(42)).toEqual([]);
  });

  it("delegates loadScenarios to loadOpenApiScenarios: missing path → []", async () => {
    const plugin = new OpenApiLoaderPlugin();
    expect(await plugin.loadScenarios("/nonexistent/spec.yaml")).toEqual([]);
  });
});
