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
  abstract readonly location: L;
  abstract readonly originalValue: V;
  abstract readonly allowedTampers: (typeof TamperMethod)[];
}

// --- Named parameters (query, form, header) ---
class QueryParameter extends InspectionParameter<{ name: string }, string> {
  constructor(
    readonly location: { name: string },
    readonly originalValue: string,
    readonly allowedTampers: (typeof TamperMethod)[],
  ) {
    super();
  }
}

class FormParameter extends InspectionParameter<{ name: string }, string> {
  constructor(
    readonly location: { name: string },
    readonly originalValue: string,
    readonly allowedTampers: (typeof TamperMethod)[],
  ) {
    super();
  }
}

class HeaderParameter extends InspectionParameter<{ name: string }, string> {
  constructor(
    readonly location: { name: string },
    readonly originalValue: string,
    readonly allowedTampers: (typeof TamperMethod)[],
  ) {
    super();
  }
}

// --- JSON parameters ---
type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonArray | JsonObject;
type JsonArray = JsonValue[];
type JsonObject = { [key: string]: JsonValue };

class JsonPrimitiveParameter extends InspectionParameter<{ path: string[] }, JsonPrimitive> {
  constructor(
    readonly location: { path: string[] },
    readonly originalValue: JsonPrimitive,
    readonly allowedTampers: (typeof TamperMethod)[],
  ) {
    super();
  }
}

class JsonArrayParameter extends InspectionParameter<{ path: string[] }, JsonArray> {
  constructor(
    readonly location: { path: string[] },
    readonly originalValue: JsonArray,
    readonly allowedTampers: (typeof TamperMethod)[],
  ) {
    super();
  }
}

class JsonObjectParameter extends InspectionParameter<{ path: string[] }, JsonObject> {
  constructor(
    readonly location: { path: string[] },
    readonly originalValue: JsonObject,
    readonly allowedTampers: (typeof TamperMethod)[],
  ) {
    super();
  }
}

// --- GraphQL parameters ---
class GraphQLQueryParameter extends InspectionParameter<{ field: string }, string> {
  constructor(
    readonly location: { field: string },
    readonly originalValue: string,
    readonly allowedTampers: (typeof TamperMethod)[],
  ) {
    super();
  }
}

class GraphQLVariableParameter extends InspectionParameter<{ path: string[] }, JsonValue> {
  constructor(
    readonly location: { path: string[] },
    readonly originalValue: JsonValue,
    readonly allowedTampers: (typeof TamperMethod)[],
  ) {
    super();
  }
}

// --- TamperInstruction ---
class TamperInstruction<P extends InspectionParameter<unknown, unknown> = InspectionParameter<unknown, unknown>> {
  constructor(
    readonly parameter: P,
    readonly payload: Payload,
    readonly method: typeof TamperMethod,
  ) {}
}

class QueryTamperInstruction extends TamperInstruction<QueryParameter> {}
class FormTamperInstruction extends TamperInstruction<FormParameter> {}
class HeaderTamperInstruction extends TamperInstruction<HeaderParameter> {}
class JsonPrimitiveTamperInstruction extends TamperInstruction<JsonPrimitiveParameter> {}
class JsonArrayTamperInstruction extends TamperInstruction<JsonArrayParameter> {}
class JsonObjectTamperInstruction extends TamperInstruction<JsonObjectParameter> {}
class GraphQLQueryTamperInstruction extends TamperInstruction<GraphQLQueryParameter> {}
class GraphQLVariableTamperInstruction extends TamperInstruction<GraphQLVariableParameter> {}

type NamedParameter = QueryParameter | FormParameter | HeaderParameter;
type JsonParameter = JsonPrimitiveParameter | JsonArrayParameter | JsonObjectParameter;
type GraphQLParameter = GraphQLQueryParameter | GraphQLVariableParameter;

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
  InspectionParameter,
  NamedParameter,
  JsonParameter,
  GraphQLParameter,
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

export {
  QueryParameter,
  FormParameter,
  HeaderParameter,
  JsonPrimitiveParameter,
  JsonArrayParameter,
  JsonObjectParameter,
  GraphQLQueryParameter,
  GraphQLVariableParameter,
  TamperInstruction,
  QueryTamperInstruction,
  FormTamperInstruction,
  HeaderTamperInstruction,
  JsonPrimitiveTamperInstruction,
  JsonArrayTamperInstruction,
  JsonObjectTamperInstruction,
  GraphQLQueryTamperInstruction,
  GraphQLVariableTamperInstruction,
};
