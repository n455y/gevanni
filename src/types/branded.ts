type Brand<T, B extends string> = T & { readonly __brand: B };

// --- IDs ---
type ScenarioId = Brand<string, "ScenarioId">;
const ScenarioId = (id: string) => id as ScenarioId;
type JobId = Brand<string, "JobId">;
const JobId = (id: string) => id as JobId;
type RequestId = Brand<string, "RequestId">;
const RequestId = (id: string) => id as RequestId;
type ScanId = Brand<string, "ScanId">;
const ScanId = (id: string) => id as ScanId;
type ExchangeId = Brand<string, "ExchangeId">;
const ExchangeId = (id: string) => id as ExchangeId;

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
const JobStatus = (status: "pending" | "running" | "completed" | "error") =>
  status as JobStatus;
type ScanStatus = Brand<
  "planning" | "scanning" | "completed" | "error",
  "ScanStatus"
>;
const ScanStatus = (status: "planning" | "scanning" | "completed" | "error") =>
  status as ScanStatus;

// --- Semantic ---
type Payload = Brand<string, "Payload">;
const Payload = (value: string) => value as Payload;
type Evidence = Brand<string, "Evidence">;
const Evidence = (value: string) => value as Evidence;
type ErrorMessage = Brand<string, "ErrorMessage">;
const ErrorMessage = (value: string) => value as ErrorMessage;
export type { Brand };

export {
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
  ReplaceValue,
  AppendValue,
  PrependValue,
};
