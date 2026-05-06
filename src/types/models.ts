import { ScenarioType, ParameterType } from "./branded.js";
import type {
  ScenarioId,
  JobId,
  RequestId,
  ScanId,
  ExchangeId,
  TamperMethod,
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
interface InspectionParameter<
  P extends typeof ParameterType = typeof ParameterType,
  L = unknown,
  V = unknown,
> {
  type: P;
  location: L;
  originalValue: V;
  allowedTampers: TamperMethod[];
}

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonArray | JsonObject;
type JsonArray = JsonValue[];
type JsonObject = { [key: string]: JsonValue };

// --- TamperInstruction ---
interface TamperInstruction {
  parameter: InspectionParameter;
  payload: Payload;
  method: TamperMethod;
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
  parameters: InspectionParameter[];
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
  InspectionParameter,
  JsonPrimitive,
  JsonArray,
  JsonObject,
  JsonValue,
  TamperInstruction,
  HttpRequest,
  HttpResponse,
  Exchange,
  Finding,
  Job,
  ScanState,
  ScanConfig,
  PluginConfig,
};
