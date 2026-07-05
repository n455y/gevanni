import type { DiffStrategyConfig } from "../../../types/models.ts";

// --- OpenAPI 3.x types (subset) ---

export interface OpenApiParameter {
  name: string;
  in: "query" | "header" | "path" | "cookie";
  required?: boolean;
  schema?: { type?: string; [key: string]: unknown };
  example?: unknown;
}

export interface OpenApiRequestBody {
  contentType: string;
  schema?: { type?: string; [key: string]: unknown };
  example?: unknown;
}

export interface OpenApiLink {
  targetOperationId: string;
  parameters: Record<string, string>;
  requestBody?: Record<string, string>;
}

export interface OpenApiOperation {
  baseUrl: string;
  method: string;
  path: string;
  operationId?: string;
  summary?: string;
  parameters: OpenApiParameter[];
  requestBody?: OpenApiRequestBody;
  bodyVariants?: OpenApiRequestBody[];
  links?: OpenApiLink[];
  security?: string[];
}

// components/securitySchemes/<name> の解決に必要な情報。
// x-gevanni-token を持つ scheme は、scenario 内で token を返す step の
// レスポンスから token を抽出し、その scheme で保護された以降の operation へ
// type/scheme に応じた送信形式（Bearer 等）で自動注入される。
export interface OpenApiSecurityScheme {
  type: string;
  scheme?: string;
  in?: string;
  name?: string;
  tokenExpr?: string;
}

export interface OpenApiStep {
  operation: OpenApiOperation;
  link?: OpenApiLink;
}

export interface OpenApiSecondOrder {
  steps: OpenApiStep[];
}

export interface OpenApiScenarioSource {
  steps: OpenApiStep[];
  scannable: boolean;
  diff?: DiffStrategyConfig;
  secondOrders?: OpenApiSecondOrder[];
  securitySchemes?: Record<string, OpenApiSecurityScheme>;
}

export type MatchExpr = Record<string, unknown> | Record<string, unknown>[] | number;

export interface StepDef {
  ref: string;
  match?: MatchExpr;
}
