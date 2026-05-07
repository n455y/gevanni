import { SingleCommand } from "../core/command.js";
import type { InspectionParameter, Finding, TamperInstruction, HttpRequest, HttpResponse } from "../types/models.js";

interface RunInspectionPayload {
  signatureName: string;
  parameters: InspectionParameter<unknown, unknown>[];
  replay: (instructions: TamperInstruction[]) => Promise<{
    request: HttpRequest;
    response: HttpResponse;
  }>;
}

class RunInspectionCommand extends SingleCommand<Finding> {
  readonly type = "runInspection";
  constructor(readonly payload: RunInspectionPayload) { super(); }
}

export { RunInspectionCommand, type RunInspectionPayload };
