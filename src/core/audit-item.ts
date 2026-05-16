import type { AuditParameter } from "../types/models.ts";
import type { SignatureId } from "../types/branded.ts";

interface AuditItem {
  readonly signatureName: SignatureId;
  readonly parameter: AuditParameter;
}

export type { AuditItem };
