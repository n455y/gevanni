import fs from "node:fs";
import crypto from "node:crypto";
import type { Scenario } from "../../types/models.ts";
import { PostmanScenarioType } from "../scenario/postman.ts";
import { ScenarioId } from "../../types/branded.ts";
import type { ScenarioLoaderPlugin, PluginContext } from "../../core/plugin.ts";

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

// --- Plugin ---

export class PostmanLoaderPlugin implements ScenarioLoaderPlugin {
  readonly name = "postman-loader";

  async init(_context: PluginContext): Promise<void> {}

  async load(source: unknown): Promise<Scenario[]> {
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

    return flatItems.map((item) => ({
      id: scenarioId(),
      name: item.name ?? "unnamed",
      type: PostmanScenarioType,
      source: { items: [item] },
    }));
  }
}
