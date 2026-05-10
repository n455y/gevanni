import { SingleCommand } from "../core/command.js";
import type {
  AuditTarget,
  Finding,
  AuditMutation,
  HttpRequest,
  HttpResponse,
} from "../types/models.js";

interface RunAuditPayload {
  signatureName: string;
  target: AuditTarget;
  replay: (mutations: AuditMutation[]) => Promise<{
    request: HttpRequest;
    response: HttpResponse;
  }>;
}

class RunAuditCommand extends SingleCommand<Finding> {
  readonly type = "runAudit";
  constructor(readonly payload: RunAuditPayload) {
    super();
  }
}

export { RunAuditCommand, type RunAuditPayload };
