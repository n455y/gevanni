import type { MutationType, Payload } from "../../../types/branded.ts";
import { AuditParameter, AuditMutation } from "../../../types/models.ts";
import { serializable } from "../../../types/serializable.ts";

export class PathParameter extends AuditParameter<{ name: string }, string> {
  static kind = "path";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): PathMutation {
    return new PathMutation(this, payload, mutationType);
  }
}
serializable(PathParameter);

export class PathMutation extends AuditMutation<PathParameter> {}
