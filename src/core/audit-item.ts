import type { AuditParameter } from "../types/models.ts";
import type { SignatureId, SignatureGroupId } from "../types/branded.ts";

interface AuditItem {
  readonly signatureName: SignatureId;
  readonly parameter: AuditParameter;
  readonly groups: readonly SignatureGroupId[];
}

export type { AuditItem };
