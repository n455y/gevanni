import { ScenarioType } from "./branded.ts";
import type {
  AnyMutationType,
  ScenarioId,
  JobId,
  ScanId,
  ExchangeId,
  JobStatus,
  ScanStatus,
  Payload,
  ErrorMessage,
} from "./branded.ts";
import { SerializableBase, type SerializableValue } from "./serializable.ts";

// --- Scenario ---
export interface Scenario {
  id: ScenarioId;
  name: string;
  type: ScenarioType;
  source: unknown;
}

// --- JSON types ---
export type JsonPrimitive = string | number | boolean | null;
export type JsonArray = JsonValue[];
export type JsonObject = { [key: string]: JsonValue };
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;

// --- AuditParameter ---
export class AuditParameter<
  L extends SerializableValue = SerializableValue,
  V extends SerializableValue = SerializableValue,
> extends SerializableBase<{
  location: L;
  originalValue: V;
  allowedMutations: AnyMutationType[];
}> {
  static base = "audit-parameter";
  readonly location: L;
  readonly originalValue: V;
  readonly allowedMutations: AnyMutationType[];
  constructor(
    location: L,
    originalValue: V,
    allowedMutations: AnyMutationType[],
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
    allowedMutations: AnyMutationType[];
  }) {
    return new this(
      serialized.location,
      serialized.originalValue,
      serialized.allowedMutations,
    );
  }

  createMutation(
    _payload: Payload,
    _method: AnyMutationType,
  ): AuditMutation {
    throw new Error("Not implemented");
  }
}

// --- AuditMutation ---
export abstract class AuditMutation<
  P extends AuditParameter = AuditParameter,
> {
  readonly parameter: P;
  readonly payload: Payload;
  readonly method: AnyMutationType;
  constructor(
    parameter: P,
    payload: Payload,
    method: AnyMutationType,
  ) {
    this.parameter = parameter;
    this.payload = payload;
    this.method = method;
  }
}

// --- HTTP ---
export interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Buffer | null;
}

export interface HttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Buffer | null;
}

// --- Exchange ---
export interface Exchange {
  id: ExchangeId;
  request: HttpRequest;
  response: HttpResponse;
}

// --- Evidence ---
export interface Evidence {
  judgmentId: string;
  exchanges: Exchange[];
  evidenceExchanges: Exchange[];
}

// --- Finding ---
export interface Finding {
  vulnerable: boolean;
  evidence: Evidence;
  request: HttpRequest;
  response: HttpResponse;
}

// --- Job ---
export interface Job {
  id: JobId;
  scanId: ScanId;
  scenarioId: ScenarioId;
  signatureName: string;
  parameter: AuditParameter;
  status: JobStatus;
  finding: Finding | null;
  error: ErrorMessage | null;
  createdAt: Date;
  updatedAt: Date;
}

// --- ScanState ---
export interface ScanState {
  id: ScanId;
  status: ScanStatus;
  startedAt: Date;
  updatedAt: Date;
}

// --- SerializedScanState ---
export interface SerializedScanState {
  id: ScanId;
  status: ScanStatus;
  startedAt: number;
  updatedAt: number;
}

export function serializeScanState(state: ScanState): SerializedScanState {
  return {
    ...state,
    startedAt: state.startedAt.getTime(),
    updatedAt: state.updatedAt.getTime(),
  };
}

export function deserializeScanState(data: SerializedScanState): ScanState {
  return {
    ...data,
    startedAt: new Date(data.startedAt),
    updatedAt: new Date(data.updatedAt),
  };
}

// --- ScanConfig ---
export interface ScanConfig {
  concurrency: number;
  plugins: PluginConfig[];
  scenarioSources: unknown[];
}

export interface PluginConfig {
  type: string;
  name: string;
  options: Record<string, unknown>;
}

// --- Serialized Job ---

export interface SerializedJob {
  id: JobId;
  scanId: ScanId;
  scenarioId: ScenarioId;
  signatureName: string;
  parameter: { base: string; kind: string; serialized: SerializableValue };
  status: JobStatus;
  finding: Finding | null;
  error: ErrorMessage | null;
  createdAt: number;
  updatedAt: number;
}

export function serializeJob(job: Job): SerializedJob {
  return {
    ...job,
    parameter: job.parameter.serialize(),
    createdAt: job.createdAt.getTime(),
    updatedAt: job.updatedAt.getTime(),
  };
}

export function deserializeJob(data: SerializedJob): Job {
  return {
    ...data,
    parameter: AuditParameter.deserialize(data.parameter),
    createdAt: new Date(data.createdAt),
    updatedAt: new Date(data.updatedAt),
  };
}
