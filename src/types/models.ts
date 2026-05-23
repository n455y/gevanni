import { ScenarioType, defineMutationType } from "./branded.ts";
import type {
  ScenarioId,
  JobId,
  ScanId,
  ExchangeId,
  Payload,
  ErrorMessage,
  MutationType,
  SignatureId,
} from "./branded.ts";
import { SerializableBase, type SerializableValue } from "./serializable.ts";

// --- Enum-like constants ---

export const JobStatus = {
  Pending: "pending",
  Running: "running",
  Completed: "completed",
  Error: "error",
} as const;
export type JobStatus = (typeof JobStatus)[keyof typeof JobStatus];

export const ScanStatus = {
  Planning: "planning",
  Scanning: "scanning",
  Completed: "completed",
  Error: "error",
} as const;
export type ScanStatus = (typeof ScanStatus)[keyof typeof ScanStatus];

// --- Payload builtins ---

type StringPayload = Payload<string>;
type NumberPayload = Payload<number>;
type BooleanPayload = Payload<boolean>;
type NullPayload = Payload<null>;

export const BuiltinPayload = {
  String: (v: string) => v as StringPayload,
  Number: (v: number) => v as NumberPayload,
  Boolean: (v: boolean) => v as BooleanPayload,
  Null: () => null as NullPayload,
} as const;
export namespace BuiltinPayload {
  export type String = StringPayload;
  export type Number = NumberPayload;
  export type Boolean = BooleanPayload;
  export type Null = NullPayload;
}

// --- MutationType builtins ---

export const BuiltinMutationType = {
  ReplaceValue: defineMutationType("ReplaceValue"),
  AppendValue: defineMutationType<StringPayload>("AppendValue"),
  PrependValue: defineMutationType<StringPayload>("PrependValue"),
} as const;

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
  allowedMutations: MutationType[];
}> {
  static base = "audit-parameter";
  readonly location: L;
  readonly originalValue: V;
  readonly allowedMutations: MutationType[];
  constructor(location: L, originalValue: V, allowedMutations: MutationType[]) {
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

  createMutation<P extends Payload>(
    _payload: P,
    _mutationType: MutationType<P>,
  ): AuditMutation {
    throw new Error("Not implemented");
  }
}

// --- AuditMutation ---
export abstract class AuditMutation<P extends AuditParameter = AuditParameter> {
  readonly parameter: P;
  readonly payload: Payload;
  readonly mutationType: MutationType;
  constructor(parameter: P, payload: Payload, mutationType: MutationType) {
    this.parameter = parameter;
    this.payload = payload;
    this.mutationType = mutationType;
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

// --- ReplayResult ---
export class ReplayResult {
  readonly exchange: Exchange;
  readonly secondOrderExchanges: Exchange[];
  constructor(exchange: Exchange, secondOrderExchanges: Exchange[] = []) {
    this.exchange = exchange;
    this.secondOrderExchanges = secondOrderExchanges;
  }

  get allExchanges(): Exchange[] {
    return [this.exchange, ...this.secondOrderExchanges];
  }
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
  signatureName: SignatureId;
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

export interface PluginConfig<T = Record<string, unknown>> {
  type: string;
  name: string;
  options: T;
}

// --- Serialized Job ---

export interface SerializedJob {
  id: JobId;
  scanId: ScanId;
  scenarioId: ScenarioId;
  signatureName: SignatureId;
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
