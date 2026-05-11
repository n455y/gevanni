declare const __brand: unique symbol;
export type Brand<T, B extends string> = T & { readonly [__brand]: B };

// --- IDs ---
export type ScenarioId = Brand<string, "ScenarioId">;
export const ScenarioId = (id: string) => id as ScenarioId;
export type JobId = Brand<string, "JobId">;
export const JobId = (id: string) => id as JobId;
export type ScanId = Brand<string, "ScanId">;
export const ScanId = (id: string) => id as ScanId;
export type ExchangeId = Brand<string, "ExchangeId">;
export const ExchangeId = (id: string) => id as ExchangeId;

// --- Enum-like (fixed values + Brand) ---

export type ScenarioType = Brand<string, "ScenarioType">;
export const ScenarioType = (type: string) => type as ScenarioType;

// --- Payload ---
export type Payload<T = unknown> = Brand<T, "Payload">;

type StringPayload = Payload<string>;
type NumberPayload = Payload<number>;
type BooleanPayload = Payload<boolean>;
type NullPayload = Payload<null>;

export const BuiltinPayload = {
  String: (v: string) => v as StringPayload,
  Number: (v: number) => v as NumberPayload,
  Boolean: (v: boolean) => v as BooleanPayload,
  Null: null as NullPayload,
} as const;
export namespace BuiltinPayload {
  export type String = StringPayload;
  export type Number = NumberPayload;
  export type Boolean = BooleanPayload;
  export type Null = NullPayload;
}

// --- MutationType ---
export type AnyMutationType = string & { readonly __brand: "MutationType" };
export type MutationType<P extends Payload = Payload> = AnyMutationType & {
  readonly __accepts?: (payload: P) => void;
};
export function defineMutationType<P extends Payload>(
  name: string,
): MutationType<P> {
  return name as MutationType<P>;
}

export const BuiltinMutationType = {
  ReplaceValue: defineMutationType<Payload>("ReplaceValue"),
  AppendValue: defineMutationType<StringPayload>("AppendValue"),
  PrependValue: defineMutationType<StringPayload>("PrependValue"),
} as const;

export const JobStatus = {
  Pending: "pending",
  Running: "running",
  Completed: "completed",
  Error: "error",
} as const;
export type JobStatus = (typeof JobStatus)[keyof typeof JobStatus];
export const ScanStatus = {
  Planning: "planning",
  Scanning: "scanning",
  Completed: "completed",
  Error: "error",
} as const;
export type ScanStatus = (typeof ScanStatus)[keyof typeof ScanStatus];

// --- Semantic ---
export type ErrorMessage = Brand<string, "ErrorMessage">;
export const ErrorMessage = (value: string) => value as ErrorMessage;
