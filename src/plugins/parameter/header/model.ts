import type { MutationType, Payload } from "../../../types/branded.ts";
import { AuditParameter, AuditMutation } from "../../../types/models.ts";
import { serializable } from "../../../types/serializable.ts";

export class HeaderParameter extends AuditParameter<{ name: string }, string> {
  static kind = "header";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): HeaderMutation {
    return new HeaderMutation(this, payload, mutationType);
  }
}
serializable(HeaderParameter);

export class HeaderMutation extends AuditMutation<HeaderParameter> {}
