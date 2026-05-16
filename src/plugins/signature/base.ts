import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/run-audit.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import type { AuditParameter, Finding } from "../../types/models.ts";
import type { SignatureId } from "../../types/branded.ts";

export abstract class SignaturePlugin implements Plugin {
  abstract readonly name: SignatureId;

  protected abstract filterParameters(
    parameters: AuditParameter[],
  ): AuditParameter[];

  protected abstract runAudit(context: RunAuditContext): Promise<Finding>;

  async init(context: PluginContext): Promise<void> {
    context.commandBus.register(CreateAuditItemsCommand, async (cmd) => {
      return this.filterParameters(cmd.parameters).map((parameter) => ({
        signatureName: this.name,
        parameter,
      }));
    });

    context.commandBus.register(RunAuditCommand, this.name, async (cmd) => {
      return this.runAudit(cmd.context);
    });
  }
}
