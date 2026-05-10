import type { AuditTarget } from "../types/models.ts";

interface AuditItem {
  readonly signatureName: string;
  readonly target: AuditTarget;
}

export type { AuditItem };
