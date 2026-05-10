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

export type MutationType = Brand<string, "MutationType">;
export const MutationType = (type: string) => type as MutationType;

export const BuiltinMutationType = {
  ReplaceValue: MutationType("ReplaceValue"),
  AppendValue: MutationType("AppendValue"),
  PrependValue: MutationType("PrependValue"),
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
type Payload = Brand<string, "Payload">;
const Payload = (value: string) => value as Payload;
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
  Payload,
  ErrorMessage,
};
