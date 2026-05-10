import { PipelineCommand } from "../core/command.js";
import type { HttpRequest, AuditMutation } from "../types/models.js";

class ApplyMutationCommand extends PipelineCommand<HttpRequest> {
  readonly type = "applyMutation";
  readonly initial: HttpRequest;
  readonly request: HttpRequest;
  readonly mutations: AuditMutation[];
  constructor(request: HttpRequest, mutations: AuditMutation[]) {
    super();
    this.request = request;
    this.mutations = mutations;
    this.initial = request;
  }
}
export { ApplyMutationCommand };
