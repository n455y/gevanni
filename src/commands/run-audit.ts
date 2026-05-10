import { SingleCommand } from "../core/command.ts";
import type {
  AuditParameter,
  Finding,
  AuditMutation,
  HttpRequest,
  HttpResponse,
} from "../types/models.ts";

interface RunAuditContext {
  signatureName: string;
  parameter: AuditParameter;
  replay: (mutations: AuditMutation[]) => Promise<{
    request: HttpRequest;
    response: HttpResponse;
  }>;
}

class RunAuditCommand extends SingleCommand<Finding> {
  readonly type = "runAudit";
  readonly context: RunAuditContext;
  constructor(context: RunAuditContext) {
    super();
    this.context = context;
  }
}

export { RunAuditCommand, type RunAuditContext };
