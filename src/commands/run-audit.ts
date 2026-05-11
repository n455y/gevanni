import { BroadcastCommand } from "../core/command.ts";
import type {
  AuditParameter,
  Finding,
  AuditMutation,
  HttpRequest,
  HttpResponse,
} from "../types/models.ts";

export interface RunAuditContext {
  signatureName: string;
  parameter: AuditParameter;
  replay: (mutations: AuditMutation[]) => Promise<{
    request: HttpRequest;
    response: HttpResponse;
  }>;
}

export class RunAuditCommand extends BroadcastCommand<Finding | null> {
  readonly type = "runAudit";
  readonly context: RunAuditContext;
  constructor(context: RunAuditContext) {
    super();
    this.context = context;
  }
}
