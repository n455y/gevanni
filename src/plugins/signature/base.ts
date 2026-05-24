import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import type { AuditParameter, Finding } from "../../types/models.ts";
import type { SignatureId, SignatureGroupId } from "../../types/branded.ts";

export interface SignaturePlugin extends Plugin {
  readonly name: SignatureId;
  readonly groups: readonly SignatureGroupId[];
}

export abstract class SignaturePluginBase implements SignaturePlugin {
  abstract readonly name: SignatureId;

  readonly groups: readonly SignatureGroupId[];

  protected get defaultGroups(): SignatureGroupId[] {
    return [];
  }

  constructor(options?: { groups?: string[] }) {
    this.groups = options?.groups?.map((g) => g as SignatureGroupId) ?? this.defaultGroups;
  }

  protected abstract filterParameters(
    parameters: AuditParameter[],
  ): AuditParameter[];

  protected abstract runAudit(context: RunAuditContext): Promise<Finding>;

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(CreateAuditItemsCommand, async (cmd) => {
      return this.filterParameters(cmd.parameters).map((parameter) => ({
        signatureName: this.name,
        parameter,
        groups: this.groups,
      }));
    });

    context.commandBus.register(RunAuditCommand, this.name, async (cmd) => {
      return this.runAudit(cmd.context);
    });
  }
}
