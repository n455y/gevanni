import type { MutationType, Payload } from "../../../types/branded.ts";
import type { JsonValue } from "../../../types/models.ts";
import { AuditParameter, AuditMutation } from "../../../types/models.ts";
import { serializable } from "../../../types/serializable.ts";

export class GraphQLQueryParameter extends AuditParameter<
  { field: string },
  string
> {
  static kind = "graphql-query";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): GraphQLQueryMutation {
    return new GraphQLQueryMutation(this, payload, mutationType);
  }
}
serializable(GraphQLQueryParameter);

export class GraphQLVariableParameter extends AuditParameter<
  { path: string[] },
  JsonValue
> {
  static kind = "graphql-variable";
  createMutation(
    payload: Payload,
    mutationType: MutationType,
  ): GraphQLVariableMutation {
    return new GraphQLVariableMutation(this, payload, mutationType);
  }
}
serializable(GraphQLVariableParameter);

export class GraphQLQueryMutation extends AuditMutation<GraphQLQueryParameter> {}
export class GraphQLVariableMutation extends AuditMutation<GraphQLVariableParameter> {}

export type GraphQLMutation =
  | GraphQLQueryMutation
  | GraphQLVariableMutation;
