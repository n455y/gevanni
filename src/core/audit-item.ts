import { AuditTarget } from "../types/models.js";

interface AuditItem {
  readonly signatureName: string;
  readonly parameter: AuditTarget;
}

export { AuditItem };
