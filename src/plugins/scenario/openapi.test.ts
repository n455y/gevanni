import { describe, it, expect } from "vitest";
import { ReplayId } from "../../types/branded.ts";
import {
  buildUrl,
  buildHeaders,
  buildBody,
  resolveRuntimeExpression,
} from "./openapi.ts";
import type {
  OpenApiOperation,
  OpenApiRequestBody,
} from "../loader/openapi-loader.ts";
import type { HttpResponse } from "../../types/models.ts";

function mockResponse(body: Record<string, unknown>): HttpResponse {
  return {
    statusCode: 200,
    headers: { "content-type": "application/json" },
    body: Buffer.from(JSON.stringify(body)),
  };
}

describe("resolveRuntimeExpression", () => {
  it("extracts value from response body via JSON Pointer", () => {
    const res = mockResponse({ id: 42, name: "Alice" });
    expect(resolveRuntimeExpression("$response.body#/id", res)).toBe("42");
    expect(resolveRuntimeExpression("$response.body#/name", res)).toBe("Alice");
  });

  it("extracts nested values", () => {
    const res = mockResponse({ data: { token: "abc123" } });
    expect(
      resolveRuntimeExpression("$response.body#/data/token", res),
    ).toBe("abc123");
  });

  it("extracts from response headers", () => {
    const res = mockResponse({});
    res.headers["x-request-id"] = "req-999";
    expect(
      resolveRuntimeExpression("$response.header#/x-request-id", res),
    ).toBe("req-999");
  });

  it("returns empty string for missing pointer", () => {
    const res = mockResponse({ id: 1 });
    expect(resolveRuntimeExpression("$response.body#/missing", res)).toBe("");
  });

  it("returns empty string for invalid JSON body", () => {
    const res: HttpResponse = {
      statusCode: 200,
      headers: {},
      body: Buffer.from("not json"),
    };
    expect(resolveRuntimeExpression("$response.body#/id", res)).toBe("");
  });
});

describe("buildUrl", () => {
  it("builds simple URL without parameters", () => {
    const op: OpenApiOperation = {
      baseUrl: "https://api.example.com",
      method: "GET",
      path: "/users",
      parameters: [],
    };
    expect(buildUrl(op)).toBe("https://api.example.com/users");
  });

  it("resolves path parameters", () => {
    const op: OpenApiOperation = {
      baseUrl: "https://api.example.com",
      method: "GET",
      path: "/users/{id}",
      parameters: [
        { name: "id", in: "path", schema: { type: "integer" } },
      ],
    };
    expect(buildUrl(op)).toBe("https://api.example.com/users/1");
  });

  it("uses overrides for parameters", () => {
    const op: OpenApiOperation = {
      baseUrl: "https://api.example.com",
      method: "GET",
      path: "/users/{id}",
      parameters: [
        { name: "id", in: "path", schema: { type: "integer" } },
      ],
    };
    expect(buildUrl(op, { id: "42" })).toBe("https://api.example.com/users/42");
  });

  it("appends query parameters", () => {
    const op: OpenApiOperation = {
      baseUrl: "https://api.example.com",
      method: "GET",
      path: "/search",
      parameters: [
        { name: "q", in: "query", schema: { type: "string" } },
        { name: "limit", in: "query", schema: { type: "integer" } },
      ],
    };
    expect(buildUrl(op)).toBe(
      "https://api.example.com/search?q=test&limit=1",
    );
  });

  it("uses example values when available", () => {
    const op: OpenApiOperation = {
      baseUrl: "https://api.example.com",
      method: "GET",
      path: "/items/{id}",
      parameters: [
        { name: "id", in: "path", schema: { type: "string" }, example: "abc-123" },
      ],
    };
    expect(buildUrl(op)).toBe("https://api.example.com/items/abc-123");
  });

  it("handles baseUrl with trailing slash", () => {
    const op: OpenApiOperation = {
      baseUrl: "https://api.example.com/",
      method: "GET",
      path: "/users",
      parameters: [],
    };
    expect(buildUrl(op)).toBe("https://api.example.com/users");
  });
});

describe("buildHeaders", () => {
  const replayId = ReplayId("test-replay-id");

  it("includes X-Gevanni-Replay-Id", () => {
    const op: OpenApiOperation = {
      baseUrl: "https://api.example.com",
      method: "GET",
      path: "/users",
      parameters: [],
    };
    const headers = buildHeaders(op, replayId);
    expect(headers["X-Gevanni-Replay-Id"]).toBe(replayId);
  });

  it("includes header parameters", () => {
    const op: OpenApiOperation = {
      baseUrl: "https://api.example.com",
      method: "GET",
      path: "/users",
      parameters: [
        { name: "Authorization", in: "header", example: "Bearer token123" },
      ],
    };
    const headers = buildHeaders(op, replayId);
    expect(headers["Authorization"]).toBe("Bearer token123");
  });

  it("uses overrides for header parameters", () => {
    const op: OpenApiOperation = {
      baseUrl: "https://api.example.com",
      method: "GET",
      path: "/users",
      parameters: [
        { name: "Authorization", in: "header", example: "Bearer old" },
      ],
    };
    const headers = buildHeaders(op, replayId, {
      Authorization: "Bearer new",
    });
    expect(headers["Authorization"]).toBe("Bearer new");
  });

  it("sets Content-Type when requestBody exists", () => {
    const op: OpenApiOperation = {
      baseUrl: "https://api.example.com",
      method: "POST",
      path: "/users",
      parameters: [],
      requestBody: { contentType: "application/json", schema: { type: "object" } },
    };
    const headers = buildHeaders(op, replayId);
    expect(headers["Content-Type"]).toBe("application/json");
  });
});

describe("buildBody", () => {
  it("returns null when no requestBody", () => {
    expect(buildBody(undefined)).toBeNull();
  });

  it("stringifies object body", () => {
    const body: OpenApiRequestBody = {
      contentType: "application/json",
      schema: { type: "object" },
    };
    expect(buildBody(body)).toBe("{}");
  });

  it("returns string example as-is", () => {
    const body: OpenApiRequestBody = {
      contentType: "text/plain",
      example: "hello world",
    };
    expect(buildBody(body)).toBe("hello world");
  });

  it("applies overrides to object body", () => {
    const body: OpenApiRequestBody = {
      contentType: "application/json",
      schema: { type: "object", properties: { uuid: { type: "string" } } },
    };
    const result = buildBody(body, { uuid: "abc-123" });
    expect(result).toBe('{"uuid":"abc-123"}');
  });

  it("overrides add fields even when schema has no matching property", () => {
    const body: OpenApiRequestBody = {
      contentType: "application/json",
      schema: { type: "object" },
    };
    const result = buildBody(body, { token: "xyz" });
    expect(result).toBe('{"token":"xyz"}');
  });

  it("ignores empty overrides", () => {
    const body: OpenApiRequestBody = {
      contentType: "application/json",
      schema: { type: "object" },
    };
    expect(buildBody(body, {})).toBe("{}");
    expect(buildBody(body, undefined)).toBe("{}");
  });
});
