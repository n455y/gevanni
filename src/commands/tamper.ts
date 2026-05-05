import { PipelineCommand } from "../core/command.js";
import type { HttpRequest, TamperInstruction } from "../types/models.js";

class ApplyTamperCommand extends PipelineCommand<HttpRequest> {
  readonly type = "applyTamper";
  readonly initial: HttpRequest;
  constructor(readonly request: HttpRequest, readonly instructions: TamperInstruction[]) {
    super();
    this.initial = request;
  }
}
export { ApplyTamperCommand };
