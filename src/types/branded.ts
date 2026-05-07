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

export type TamperMethod = Brand<string, "TamperMethod">;
export const TamperMethod = (method: string) => method as TamperMethod;

const ReplaceValue = TamperMethod("ReplaceValue");
const AppendValue = TamperMethod("AppendValue");
const PrependValue = TamperMethod("PrependValue");

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

export {
  Brand,
  ScenarioId,
  JobId,
  RequestId,
  ScanId,
  ExchangeId,
  ReplaceValue,
  AppendValue,
  PrependValue,
  JobStatus,
  ScanStatus,
  Payload,
  Evidence,
  ErrorMessage,
  IsoDateTime,
};
