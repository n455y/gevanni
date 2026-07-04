import { PipelineCommand } from "../core/command.ts";
import type { HttpRequest, AuditMutation } from "../types/models.ts";

export class ApplyMutationCommand extends PipelineCommand<HttpRequest> {
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
