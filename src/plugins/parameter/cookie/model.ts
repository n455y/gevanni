import type { MutationType, Payload } from "../../../types/branded.ts";
import { AuditParameter, AuditMutation } from "../../../types/models.ts";
import { serializable } from "../../../types/serializable.ts";

export class CookieParameter extends AuditParameter<{ name: string }, string> {
  static kind = "cookie";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): CookieMutation {
    return new CookieMutation(this, payload, mutationType);
  }
}
serializable(CookieParameter);

export class CookieMutation extends AuditMutation<CookieParameter> {}

/**
 * Shared by both the parser (extracting parameters) and the mutation plugin
 * (reading current values to modify).
 */
export function parseCookieHeader(header: string): Map<string, string> {
  const cookies = new Map<string, string>();

  for (const pair of header.split(";")) {
    const trimmed = pair.trim();
    if (!trimmed) continue;
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) continue;
    const name = trimmed.slice(0, eqIndex).trim();
    const value = trimmed.slice(eqIndex + 1).trim();
    cookies.set(name, value);
  }

  return cookies;
}
