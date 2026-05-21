import type { AuditMutation } from "../types/models.ts";
import { SingleCommand } from "../core/command.ts";

export interface MutationProxy {
  port: number;
  close: () => void;
}

export class CreateProxyCommand extends SingleCommand<MutationProxy> {
  readonly type = "createProxy";
  constructor(readonly mutations: AuditMutation[]) {
    super();
  }
}
