import { ScenarioType, TamperMethod } from "./branded.js";
import type {
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
} from "./branded.js";

// --- Scenario ---
interface Scenario {
  id: ScenarioId;
  name: string;
  type: typeof ScenarioType;
  source: unknown;
}

// --- InspectionParameter ---
abstract class InspectionParameter<L, V> {
  constructor(
    readonly location: L,
    readonly originalValue: V,
    readonly allowedTampers: TamperMethod[],
  ) {}

  abstract createInstruction(
    payload: Payload,
    method: TamperMethod,
  ): TamperInstruction;
}

// --- JSON types ---
type JsonPrimitive = string | number | boolean | null;
type JsonArray = JsonValue[];
type JsonObject = { [key: string]: JsonValue };
type JsonValue = JsonPrimitive | JsonArray | JsonObject;

// --- TamperInstruction ---
abstract class TamperInstruction<
  P extends InspectionParameter<unknown, unknown> = InspectionParameter<
    unknown,
    unknown
  >,
> {
  constructor(
    readonly parameter: P,
    readonly payload: Payload,
    readonly method: TamperMethod,
  ) {}
}

// --- HTTP ---
interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Buffer | null;
}

interface HttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Buffer | null;
}

// --- Exchange ---
interface Exchange {
  id: ExchangeId;
  request: HttpRequest;
  response: HttpResponse;
}

// --- Finding ---
interface Finding {
  vulnerable: boolean;
  evidence: Evidence;
  request: HttpRequest;
  response: HttpResponse;
}

// --- Job ---
interface Job {
  id: JobId;
  scanId: ScanId;
  scenarioId: ScenarioId;
  requestId: RequestId;
  signatureName: string;
  parameters: InspectionParameter<unknown, unknown>[];
  status: JobStatus;
  finding: Finding | null;
  error: ErrorMessage | null;
  createdAt: IsoDateTime;
  updatedAt: IsoDateTime;
}

// --- ScanState ---
interface ScanState {
  id: ScanId;
  status: ScanStatus;
  startedAt: IsoDateTime;
  updatedAt: IsoDateTime;
}

// --- ScanConfig ---
interface ScanConfig {
  concurrency: number;
  plugins: PluginConfig[];
  scenarioSources: unknown[];
}

interface PluginConfig {
  type: string;
  name: string;
  options: Record<string, unknown>;
}

export type {
  Scenario,
  JsonPrimitive,
  JsonArray,
  JsonObject,
  JsonValue,
  HttpRequest,
  HttpResponse,
  Exchange,
  Finding,
  Job,
  ScanState,
  ScanConfig,
  PluginConfig,
};

export { InspectionParameter, TamperInstruction };
