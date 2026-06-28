import type { AuditMutation } from "../types/models.ts";
import { SingleCommand } from "../core/command.ts";

export interface MutationProxy {
  port: number;
  close: () => void;
}

export class CreateProxyCommand extends SingleCommand<MutationProxy> {
  readonly type = "createProxy";
  readonly mutations: AuditMutation[];
  constructor(mutations: AuditMutation[]) {
    super();
    this.mutations = mutations;
  }
}
