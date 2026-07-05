// --- Helpers ---

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function mergeAllOf(schemas: unknown[]): Record<string, unknown> {
  const allProperties: Record<string, unknown> = {};
  const allRequired: string[] = [];
  const extra: Record<string, unknown> = { type: "object" };

  for (const s of schemas) {
    if (!isObject(s)) continue;
    if (isObject(s.properties)) {
      Object.assign(allProperties, s.properties);
    }
    if (Array.isArray(s.required)) {
      allRequired.push(...(s.required as string[]));
    }
    for (const [k, v] of Object.entries(s)) {
      if (k !== "properties" && k !== "required" && k !== "allOf") {
        extra[k] = v;
      }
    }
  }

  if (Object.keys(allProperties).length > 0) extra.properties = allProperties;
  if (allRequired.length > 0) extra.required = [...new Set(allRequired)];
  return extra;
}

export function resolveSchema(schema: unknown): Record<string, unknown> | undefined {
  if (!isObject(schema)) return undefined;
  if (Array.isArray(schema.allOf)) return mergeAllOf(schema.allOf);
  return { ...schema };
}

export function expandSchemaVariants(schema: unknown, resolver: { resolve<T>(node: unknown, depth?: number): T | undefined }): Record<string, unknown>[] {
  const deref = resolver.resolve<Record<string, unknown>>(schema);
  if (!deref) return [{}];
  const resolved = resolveSchema(deref);
  if (!resolved) return [{}];
  const variants = resolved.oneOf;
  if (!Array.isArray(variants)) return [resolved];
  return variants
    .map((v) => {
      const d = resolver.resolve<Record<string, unknown>>(v);
      return d ? resolveSchema(d) : undefined;
    })
    .filter((v): v is Record<string, unknown> => v !== undefined);
}

export function defaultValueForSchema(
  schema?: { type?: string; [key: string]: unknown },
  example?: unknown,
): unknown {
  if (example !== undefined) return example;
  if (!schema) return "test";

  if (schema.default !== undefined) return schema.default;
  if (Array.isArray(schema.enum) && schema.enum.length > 0) return schema.enum[0];

  if (Array.isArray(schema.allOf)) {
    return defaultValueForSchema(mergeAllOf(schema.allOf));
  }

  if (Array.isArray(schema.oneOf)) {
    const variants = schema.oneOf as unknown[];
    const first = variants[0];
    return first ? defaultValueForSchema(first as { type?: string; [key: string]: unknown }) : "test";
  }

  switch (schema.type) {
    case "integer":
    case "number":
      return 1;
    case "boolean":
      return true;
    case "array":
      return [];
    case "object": {
      if (isObject(schema.properties)) {
        const obj: Record<string, unknown> = {};
        for (const [key, propSchema] of Object.entries(schema.properties)) {
          obj[key] = defaultValueForSchema(
            propSchema as { type?: string; [key: string]: unknown },
          );
        }
        return obj;
      }
      return {};
    }
    default:
      return "test";
  }
}
