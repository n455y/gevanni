export type Brand<T, B extends string> = T & { readonly __brand: B };

// --- IDs ---
export type ScenarioId = Brand<string, "ScenarioId">;
export const ScenarioId = (id: string) => id as ScenarioId;
export type SignatureJobId = Brand<string, "SignatureJobId">;
export const SignatureJobId = (id: string) => id as SignatureJobId;
export type ScanId = Brand<string, "ScanId">;
export const ScanId = (id: string) => id as ScanId;
export type ExchangeId = Brand<string, "ExchangeId">;
export const ExchangeId = (id: string) => id as ExchangeId;
export type ReplayId = Brand<string, "ReplayId">;
export const ReplayId = (id: string) => id as ReplayId;
export type SignatureGroupId = Brand<string, "SignatureGroupId">;
export const SignatureGroupId = (id: string) => id as SignatureGroupId;

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
