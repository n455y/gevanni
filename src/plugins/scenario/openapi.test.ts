import { describe, it, expect } from "vitest";
import { ReplayId } from "../../types/branded.ts";
import {
  buildUrl,
  buildHeaders,
  buildBody,
} from "./openapi.ts";
import type {
  OpenApiOperation,
  OpenApiRequestBody,
} from "../loader/openapi-loader.ts";

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
    const headers = buildHeaders(op, 8080, replayId);
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
    const headers = buildHeaders(op, 8080, replayId);
    expect(headers["Authorization"]).toBe("Bearer token123");
  });

  it("sets Content-Type when requestBody exists", () => {
    const op: OpenApiOperation = {
      baseUrl: "https://api.example.com",
      method: "POST",
      path: "/users",
      parameters: [],
      requestBody: { contentType: "application/json", schema: { type: "object" } },
    };
    const headers = buildHeaders(op, 8080, replayId);
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
});
