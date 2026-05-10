import { AuditTarget } from "../types/models.js";

interface AuditItem {
  readonly signatureName: string;
  readonly target: AuditTarget;
}

export { AuditItem };
