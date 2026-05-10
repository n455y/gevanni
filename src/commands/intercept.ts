import { SingleCommand } from "../core/command.js";
import type { HttpRequest, AuditMutation, HttpResponse } from "../types/models.js";

class InterceptCommand extends SingleCommand<{ request: HttpRequest; response: HttpResponse }> {
  readonly type = "intercept";
  constructor(readonly request: HttpRequest, readonly mutations: AuditMutation[]) { super(); }
}
export { InterceptCommand };
