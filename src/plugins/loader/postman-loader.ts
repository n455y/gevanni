import fs from "node:fs";
import crypto from "node:crypto";
import type { Scenario } from "../../types/models.ts";
import { PostmanScenarioType } from "../scenario/postman.ts";
import { ScenarioId } from "../../types/branded.ts";

// --- Postman Collection types (v2.1 subset) ---

interface PostmanItem {
  name: string;
  request: unknown;
  item?: PostmanItem[];
}

interface PostmanCollection {
  info?: { name?: string };
  item?: PostmanItem[];
}

// --- Helpers ---

function scenarioId(): ScenarioId {
  return ScenarioId(crypto.randomUUID());
}

function flattenItems(items: PostmanItem[]): PostmanItem[] {
  const result: PostmanItem[] = [];
  for (const item of items) {
    if (item.item && item.item.length > 0) {
      result.push(...flattenItems(item.item));
    } else if (item.request) {
      result.push(item);
    }
  }
  return result;
}

function isPostmanCollection(data: unknown): data is PostmanCollection {
  if (typeof data !== "object" || data === null) return false;
  const obj = data as Record<string, unknown>;
  return Array.isArray(obj.item);
}

// --- Loader ---

export async function loadPostmanScenarios(source: unknown): Promise<Scenario[]> {
  if (typeof source !== "string") return [];

  let raw: string;
  try {
    raw = fs.readFileSync(source, "utf-8");
  } catch {
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }

  if (!isPostmanCollection(parsed)) return [];

  const items = parsed.item ?? [];
  const flatItems = flattenItems(items);

  return flatItems.map((item) => {
    const req = item.request as { method?: string; url?: { raw?: string } | string } | undefined;
    const method = req?.method ?? "GET";
    const url = typeof req?.url === "string" ? req.url : req?.url?.raw ?? "unknown";
    return {
      id: scenarioId(),
      name: item.name ?? "unnamed",
      type: PostmanScenarioType,
      source: { items: [item] },
      representation: `  ${item.name ?? "unnamed"}\n    ${method} ${url}`,
      diffStrategy: { type: "exact" },
    };
  });
}
