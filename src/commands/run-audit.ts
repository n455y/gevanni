import { KeyedBroadcastCommand } from "../core/command.ts";
import type {
  AuditParameter,
  Finding,
  AuditMutation,
  HttpRequest,
  HttpResponse,
} from "../types/models.ts";
import type { SignatureId } from "../types/branded.ts";

export interface RunAuditContext {
  signatureName: SignatureId;
  parameter: AuditParameter;
  replay: (mutations: AuditMutation[]) => Promise<{
    request: HttpRequest;
    response: HttpResponse;
  }>;
}

export class RunAuditCommand extends KeyedBroadcastCommand<Finding | null> {
  readonly type = "runAudit";
  readonly context: RunAuditContext;
  get key() {
    return this.context.signatureName;
  }
  constructor(context: RunAuditContext) {
    super();
    this.context = context;
  }
}
