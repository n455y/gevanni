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
import { SerializableBase, SerializableValue } from "./serializable.js";

// --- Scenario ---
interface Scenario {
  id: ScenarioId;
  name: string;
  type: typeof ScenarioType;
  source: unknown;
}

// --- JSON types ---
type JsonPrimitive = string | number | boolean | null;
type JsonArray = JsonValue[];
type JsonObject = { [key: string]: JsonValue };
type JsonValue = JsonPrimitive | JsonArray | JsonObject;

// --- InspectionParameter ---
class InspectionParameter<
  L extends SerializableValue = SerializableValue,
  V extends SerializableValue = SerializableValue,
> extends SerializableBase<{
  location: L;
  originalValue: V;
  allowedTampers: TamperMethod[];
}> {
  constructor(
    readonly location: L,
    readonly originalValue: V,
    readonly allowedTampers: TamperMethod[],
  ) {
    super();
  }
  serializeParams() {
    return {
      location: this.location,
      originalValue: this.originalValue,
      allowedTampers: this.allowedTampers,
    };
  }
  static deserializeParams<
    L extends SerializableValue,
    V extends SerializableValue,
  >(serialized: {
    location: L;
    originalValue: V;
    allowedTampers: TamperMethod[];
  }) {
    return new this(
      serialized.location,
      serialized.originalValue,
      serialized.allowedTampers,
    );
  }

  createInstruction(
    _payload: Payload,
    _method: TamperMethod,
  ): TamperInstruction {
    throw new Error("Not implemented");
  }
}

// --- TamperInstruction ---
abstract class TamperInstruction<
  P extends InspectionParameter = InspectionParameter,
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
  parameter: InspectionParameter;
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
