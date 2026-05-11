import { SingleCommand } from "../core/command.ts";
import type { HttpRequest, AuditMutation, HttpResponse } from "../types/models.ts";

export class InterceptCommand extends SingleCommand<{ request: HttpRequest; response: HttpResponse }> {
  readonly type = "intercept";
  readonly request: HttpRequest;
  readonly mutations: AuditMutation[];
  constructor(request: HttpRequest, mutations: AuditMutation[]) { super(); this.request = request; this.mutations = mutations; }
}
