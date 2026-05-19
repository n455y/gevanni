export type Brand<T, B extends string> = T & { readonly __brand: B };

// --- IDs ---
export type ScenarioId = Brand<string, "ScenarioId">;
export const ScenarioId = (id: string) => id as ScenarioId;
export type JobId = Brand<string, "JobId">;
export const JobId = (id: string) => id as JobId;
export type ScanId = Brand<string, "ScanId">;
export const ScanId = (id: string) => id as ScanId;
export type ExchangeId = Brand<string, "ExchangeId">;
export const ExchangeId = (id: string) => id as ExchangeId;
export type ReplayId = Brand<string, "ReplayId">;
export const ReplayId = (id: string) => id as ReplayId;
export type SignatureId = Brand<string, "SignatureId">;
export const SignatureId = (id: string) => id as SignatureId;

// --- Enum-like (fixed values + Brand) ---

export type ScenarioType = Brand<string, "ScenarioType">;
export const ScenarioType = (type: string) => type as ScenarioType;

// --- Payload ---
export type Payload<T = unknown> = Brand<T, "Payload">;

// --- MutationType ---
export type MutationType<P extends Payload = Payload> = Brand<
  string,
  "MutationType"
> & { readonly __payload: P };
export function defineMutationType<P extends Payload = Payload>(
  name: string,
): MutationType<P> {
  return name as any;
}


// --- Semantic ---
export type ErrorMessage = Brand<string, "ErrorMessage">;
export const ErrorMessage = (value: string) => value as ErrorMessage;
