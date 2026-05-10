type Brand<T, B extends string> = T & { readonly __brand: B };

// --- IDs ---
type ScenarioId = Brand<string, "ScenarioId">;
type JobId = Brand<string, "JobId">;
type RequestId = Brand<string, "RequestId">;
type ScanId = Brand<string, "ScanId">;
type ExchangeId = Brand<string, "ExchangeId">;

// --- Enum-like (fixed values + Brand) ---

export type ScenarioType = Brand<string, "ScenarioType">;
export const ScenarioType = (type: string) => type as ScenarioType;

export type MutationType = Brand<string, "MutationType">;
export const MutationType = (type: string) => type as MutationType;

const ReplaceValue = MutationType("ReplaceValue");
const AppendValue = MutationType("AppendValue");
const PrependValue = MutationType("PrependValue");

type JobStatus = Brand<
  "pending" | "running" | "completed" | "error",
  "JobStatus"
>;
type ScanStatus = Brand<
  "planning" | "scanning" | "completed" | "error",
  "ScanStatus"
>;

// --- Semantic ---
type Payload = Brand<string, "Payload">;
type Evidence = Brand<string, "Evidence">;
type ErrorMessage = Brand<string, "ErrorMessage">;
type IsoDateTime = Brand<string, "IsoDateTime">;

export type {
  Brand,
  ScenarioId,
  JobId,
  RequestId,
  ScanId,
  ExchangeId,
  JobStatus,
  ScanStatus,
  Payload,
  Evidence,
  ErrorMessage,
  IsoDateTime,
};

export { ReplaceValue, AppendValue, PrependValue };
