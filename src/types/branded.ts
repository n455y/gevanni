type Brand<T, B extends string> = T & { readonly __brand: B };

// --- IDs ---
type ScenarioId = Brand<string, "ScenarioId">;
const ScenarioId = (id: string) => id as ScenarioId;
type JobId = Brand<string, "JobId">;
const JobId = (id: string) => id as JobId;
type ScanId = Brand<string, "ScanId">;
const ScanId = (id: string) => id as ScanId;
type ExchangeId = Brand<string, "ExchangeId">;
const ExchangeId = (id: string) => id as ExchangeId;

// --- Enum-like (fixed values + Brand) ---

export type ScenarioType = Brand<string, "ScenarioType">;
export const ScenarioType = (type: string) => type as ScenarioType;

// --- Payload ---
export type StringPayload = Brand<string, "StringPayload">;
export type NumberPayload = Brand<number, "NumberPayload">;
export type BooleanPayload = Brand<boolean, "BooleanPayload">;
export type NullPayload = Brand<null, "NullPayload">;

export const Payload = {
  string: (v: string) => v as StringPayload,
  number: (v: number) => v as NumberPayload,
  boolean: (v: boolean) => v as BooleanPayload,
  null: () => null as NullPayload,
} as const;

export type Payload = StringPayload | NumberPayload | BooleanPayload | NullPayload;

// --- MutationType ---
export type AnyMutationType = string & { readonly __brand: "MutationType" };
export type MutationType<P extends Payload = Payload> = AnyMutationType & {
  readonly __accepts?: (payload: P) => void;
};
export function defineMutationType<P extends Payload>(name: string): MutationType<P> {
  return name as MutationType<P>;
}

export const BuiltinMutationType = {
  ReplaceValue: defineMutationType<Payload>("ReplaceValue"),
  AppendValue: defineMutationType<StringPayload>("AppendValue"),
  PrependValue: defineMutationType<StringPayload>("PrependValue"),
} as const;

const JobStatus = {
  Pending: "pending",
  Running: "running",
  Completed: "completed",
  Error: "error",
} as const;
type JobStatus = (typeof JobStatus)[keyof typeof JobStatus];
const ScanStatus = {
  Planning: "planning",
  Scanning: "scanning",
  Completed: "completed",
  Error: "error",
} as const;
type ScanStatus = (typeof ScanStatus)[keyof typeof ScanStatus];

// --- Semantic ---
type ErrorMessage = Brand<string, "ErrorMessage">;
const ErrorMessage = (value: string) => value as ErrorMessage;
export type { Brand };

export {
  ScenarioId,
  JobId,
  ScanId,
  ExchangeId,
  JobStatus,
  ScanStatus,
  ErrorMessage,
};
