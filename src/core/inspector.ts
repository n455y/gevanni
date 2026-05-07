import type { InspectionParameter, HttpRequest, HttpResponse, TamperInstruction, Finding } from "../types/models.js";

type ReplayFn = (instructions: TamperInstruction[]) => Promise<{
  request: HttpRequest;
  response: HttpResponse;
}>;

interface SignatureInspector {
  readonly signatureName: string;
  readonly parameters: InspectionParameter<unknown, unknown>[];
  inspect(replay: ReplayFn): Promise<Finding>;
}

export { SignatureInspector, ReplayFn };
