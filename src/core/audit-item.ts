import type { AuditParameter } from "../types/models.ts";
import type { SignatureGroupId, SignatureId } from "../types/branded.ts";

interface AuditItem {
  readonly signatureName: SignatureId;
  readonly parameter: AuditParameter;
  readonly categories: SignatureGroupId[];
}

export type { AuditItem };
