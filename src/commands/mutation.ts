import { PipelineCommand } from "../core/command.js";
import type { HttpRequest, AuditMutation } from "../types/models.js";

class ApplyMutationCommand extends PipelineCommand<HttpRequest> {
  readonly type = "applyMutation";
  readonly initial: HttpRequest;
  constructor(readonly request: HttpRequest, readonly mutations: AuditMutation[]) {
    super();
    this.initial = request;
  }
}
export { ApplyMutationCommand };
