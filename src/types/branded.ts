type Brand<T, B extends string> = T & { readonly __brand: B };

// --- IDs ---
type ScenarioId = Brand<string, "ScenarioId">;
type JobId = Brand<string, "JobId">;
type RequestId = Brand<string, "RequestId">;
type ScanId = Brand<string, "ScanId">;
type ExchangeId = Brand<string, "ExchangeId">;

// --- Enum-like (fixed values + Brand) ---
class ScenarioType {
  private _brand = "ScenarioType" as const;
}
type ParameterType = Brand<string, "ParameterType">;

type TamperMethod = Brand<
  "replaceValue" | "appendValue" | "prependValue",
  "TamperMethod"
>;
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
  ScenarioType,
  ParameterType,
  TamperMethod,
  JobStatus,
  ScanStatus,
  Payload,
  Evidence,
  ErrorMessage,
  IsoDateTime,
};
