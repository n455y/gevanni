import type { MutationType, Payload } from "../../../types/branded.ts";
import type {
  JsonPrimitive,
  JsonArray,
  JsonObject,
} from "../../../types/models.ts";
import { AuditParameter, AuditMutation } from "../../../types/models.ts";
import { serializable } from "../../../types/serializable.ts";

export class JsonPrimitiveParameter extends AuditParameter<
  { path: string[] },
  JsonPrimitive
> {
  static kind = "json-primitive";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): JsonPrimitiveMutation {
    return new JsonPrimitiveMutation(this, payload, mutationType);
  }
}
serializable(JsonPrimitiveParameter);

export class JsonArrayParameter extends AuditParameter<
  { path: string[] },
  JsonArray
> {
  static kind = "json-array";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): JsonArrayMutation {
    return new JsonArrayMutation(this, payload, mutationType);
  }
}
serializable(JsonArrayParameter);

export class JsonObjectParameter extends AuditParameter<
  { path: string[] },
  JsonObject
> {
  static kind = "json-object";
  createMutation<P extends Payload>(
    payload: P,
    mutationType: MutationType<P>,
  ): JsonObjectMutation {
    return new JsonObjectMutation(this, payload, mutationType);
  }
}
serializable(JsonObjectParameter);

export class JsonPrimitiveMutation extends AuditMutation<JsonPrimitiveParameter> {}
export class JsonArrayMutation extends AuditMutation<JsonArrayParameter> {}
export class JsonObjectMutation extends AuditMutation<JsonObjectParameter> {}

export type JsonMutation =
  | JsonPrimitiveMutation
  | JsonArrayMutation
  | JsonObjectMutation;
