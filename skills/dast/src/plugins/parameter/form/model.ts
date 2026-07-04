import type { MutationType, Payload } from "../../../types/branded.ts";
import { AuditParameter, AuditMutation } from "../../../types/models.ts";
import { serializable } from "../../../types/serializable.ts";

export class FormParameter extends AuditParameter<{ name: string }, string> {
  static kind = "form";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): FormMutation {
    return new FormMutation(this, payload, mutationType);
  }
}
serializable(FormParameter);

export class FormMutation extends AuditMutation<FormParameter> {}
