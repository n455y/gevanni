import type { AuditParameter } from "../types/models.ts";
import type { SignatureGroupId } from "../types/branded.ts";

interface AuditItem {
  readonly signatureName: `signature:${string}`;
  readonly parameter: AuditParameter;
  readonly groups: SignatureGroupId[];
}

export type { AuditItem };
