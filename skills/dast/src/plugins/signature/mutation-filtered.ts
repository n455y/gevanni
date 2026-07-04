import type { MutationType } from "../../types/branded.ts";
import type { AuditParameter } from "../../types/models.ts";
import { SignaturePluginBase } from "./base.ts";

export abstract class MutationFilteredSignaturePlugin extends SignaturePluginBase {
  protected abstract readonly mutationTypes: readonly MutationType[];

  protected filterParameters(parameters: AuditParameter[]) {
    return parameters.filter((parameter) =>
      this.mutationTypes.every((mt) => parameter.allowedMutations.includes(mt)),
    );
  }
}
