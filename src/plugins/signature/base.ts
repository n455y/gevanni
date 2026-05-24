import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand, ShouldSkipCommand } from "../../commands/index.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import type { AuditParameter, Finding, Job } from "../../types/models.ts";
import type { SignatureId } from "../../types/branded.ts";

export interface SignaturePlugin extends Plugin {
  readonly name: SignatureId;
}

export abstract class SignaturePluginBase implements SignaturePlugin {
  abstract readonly name: SignatureId;

  protected filterParameters(parameters: AuditParameter[]) {
    return parameters;
  }

  protected abstract runAudit(context: RunAuditContext): Promise<Finding>;

  protected shouldSkip(_completedJobs: Job[]): boolean {
    return false;
  }

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

    context.commandBus.register(ShouldSkipCommand, this.name, async (cmd) => {
      return this.shouldSkip(cmd.context.completedJobs);
    });
  }
}
