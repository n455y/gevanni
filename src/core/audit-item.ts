import type { AuditParameter } from "../types/models.ts";

interface AuditItem {
  readonly signatureName: string;
  readonly parameter: AuditParameter;
}

export type { AuditItem };
