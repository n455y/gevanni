import type { JsonValue } from "./models.ts";

export type SerializableValue = JsonValue;
const registry = new Map<
  string,
  (new (...args: any[]) => { serializeParams(): any }) & {
    deserializeParams(serialized: any): any;
  }
>();

export function serializable<
  T extends { serializeParams(): any },
  C extends new (...args: any[]) => T,
>(
  cls: C & {
    deserializeParams: (serialized: any) => any;
  } & { base: string; kind: string },
) {
  registry.set(`${cls.base}/${cls.kind}`, cls);
  return cls;
}

export abstract class SerializableBase<T extends SerializableValue> {
  static get base(): string {
    throw new Error(`\`base\` not defined in ${this.name}`);
  }
  static deserializeParams(_serialized: unknown) {
    throw new Error(`\`deserializeParams\` not implemented in ${this.name}`);
  }
  static deserialize<S, R>(
    this: { base: string; deserializeParams(serialized: S): R },
    data: {
      base: string;
      kind: string;
      serialized: S;
    },
  ): R {
    if (data.base !== this.base) {
      throw new Error(`Invalid base: expected ${this.base}, got ${data.base}`);
    }
    const cls = registry.get(`${data.base}/${data.kind}`);
    if (!cls) {
      throw new Error(`Unknown kind: ${data.kind}`);
    }
    return cls.deserializeParams(data.serialized);
  }
  abstract serializeParams(): T;
  serialize() {
    const serialized = this.serializeParams();
    if (!Object.hasOwn(this.constructor, "kind")) {
      throw new Error(`\`kind\` not defined in ${this.constructor.name}`);
    }
    return {
      base: (this.constructor as any)["base"],
      kind: (this.constructor as any)["kind"],
      serialized,
    };
  }
}
