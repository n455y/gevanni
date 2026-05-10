import { ScenarioType, MutationType } from "./branded.ts";
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
} from "./branded.ts";
import { SerializableBase, type SerializableValue } from "./serializable.ts";

// --- Scenario ---
interface Scenario {
  id: ScenarioId;
  name: string;
  type: ScenarioType;
  source: unknown;
}

// --- JSON types ---
type JsonPrimitive = string | number | boolean | null;
type JsonArray = JsonValue[];
type JsonObject = { [key: string]: JsonValue };
type JsonValue = JsonPrimitive | JsonArray | JsonObject;

// --- AuditParameter ---
class AuditParameter<
  L extends SerializableValue = SerializableValue,
  V extends SerializableValue = SerializableValue,
> extends SerializableBase<{
  location: L;
  originalValue: V;
  allowedMutations: MutationType[];
}> {
  static base = "audit-parameter";
  readonly location: L;
  readonly originalValue: V;
  readonly allowedMutations: MutationType[];
  constructor(
    location: L,
    originalValue: V,
    allowedMutations: MutationType[],
  ) {
    super();
    this.location = location;
    this.originalValue = originalValue;
    this.allowedMutations = allowedMutations;
  }
  serializeParams() {
    return {
      location: this.location,
      originalValue: this.originalValue,
      allowedMutations: this.allowedMutations,
    };
  }
  static deserializeParams<
    L extends SerializableValue,
    V extends SerializableValue,
  >(serialized: {
    location: L;
    originalValue: V;
    allowedMutations: MutationType[];
  }) {
    return new this(
      serialized.location,
      serialized.originalValue,
      serialized.allowedMutations,
    );
  }

  createMutation(
    _payload: Payload,
    _method: MutationType,
  ): AuditMutation {
    throw new Error("Not implemented");
  }
}

// --- AuditMutation ---
abstract class AuditMutation<
  P extends AuditParameter = AuditParameter,
> {
  readonly parameter: P;
  readonly payload: Payload;
  readonly method: MutationType;
  constructor(
    parameter: P,
    payload: Payload,
    method: MutationType,
  ) {
    this.parameter = parameter;
    this.payload = payload;
    this.method = method;
  }
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
  parameter: AuditParameter;
  status: JobStatus;
  finding: Finding | null;
  error: ErrorMessage | null;
  createdAt: Date;
  updatedAt: Date;
}

// --- ScanState ---
interface ScanState {
  id: ScanId;
  status: ScanStatus;
  startedAt: Date;
  updatedAt: Date;
}

// --- SerializedScanState ---
interface SerializedScanState {
  id: ScanId;
  status: ScanStatus;
  startedAt: number;
  updatedAt: number;
}

function serializeScanState(state: ScanState): SerializedScanState {
  return {
    ...state,
    startedAt: state.startedAt.getTime(),
    updatedAt: state.updatedAt.getTime(),
  };
}

function deserializeScanState(data: SerializedScanState): ScanState {
  return {
    ...data,
    startedAt: new Date(data.startedAt),
    updatedAt: new Date(data.updatedAt),
  };
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

// --- Serialized Job ---

interface SerializedJob {
  id: JobId;
  scanId: ScanId;
  scenarioId: ScenarioId;
  requestId: RequestId;
  signatureName: string;
  parameter: { base: string; kind: string; serialized: SerializableValue };
  status: JobStatus;
  finding: Finding | null;
  error: ErrorMessage | null;
  createdAt: number;
  updatedAt: number;
}

function serializeJob(job: Job): SerializedJob {
  return {
    ...job,
    parameter: job.parameter.serialize(),
    createdAt: job.createdAt.getTime(),
    updatedAt: job.updatedAt.getTime(),
  };
}

function deserializeJob(data: SerializedJob): Job {
  return {
    ...data,
    parameter: AuditParameter.deserialize(data.parameter),
    createdAt: new Date(data.createdAt),
    updatedAt: new Date(data.updatedAt),
  };
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
  SerializedJob,
  SerializedScanState,
};

export { AuditParameter, AuditMutation, serializeJob, deserializeJob, serializeScanState, deserializeScanState };
