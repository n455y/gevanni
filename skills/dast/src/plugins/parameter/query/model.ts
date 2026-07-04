import type { MutationType, Payload } from "../../../types/branded.ts";
import { AuditParameter, AuditMutation } from "../../../types/models.ts";
import { serializable } from "../../../types/serializable.ts";

export class QueryParameter extends AuditParameter<{ name: string }, string> {
  static kind = "query";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): QueryMutation {
    return new QueryMutation(this, payload, mutationType);
  }
}
serializable(QueryParameter);

export class QueryMutation extends AuditMutation<QueryParameter> {}
