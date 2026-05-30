import type { AuditParameter } from "../types/models.ts";
import type { SignatureGroupId, SignatureId } from "../types/branded.ts";

interface AuditItem {
  readonly signatureName: SignatureId;
  readonly parameter: AuditParameter;
  readonly groups: SignatureGroupId[];
}

export type { AuditItem };
