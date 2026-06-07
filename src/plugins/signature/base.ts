import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/index.ts";
import type { AuditResult } from "../../commands/run-audit.ts";
import type { CommandBus } from "../../core/command-bus.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import type { AuditParameter, Finding } from "../../types/models.ts";
import { type SignatureId, SignatureGroupId } from "../../types/branded.ts";

export interface SignaturePlugin extends Plugin {
  readonly name: SignatureId;
}

export abstract class SignaturePluginBase implements SignaturePlugin {
  abstract readonly name: SignatureId;
  protected abstract readonly groups: SignatureGroupId[];
  protected commandBus!: CommandBus;

  protected abstract runAudit(context: RunAuditContext): Promise<Finding>;

  protected filterParameters(parameters: AuditParameter[]) {
    return parameters;
  }

  protected isAlreadyChecked(context: RunAuditContext): boolean {
    const paramKey = `${context.scenarioId}:${JSON.stringify(context.parameter.location)}`;
    const sameParamJobs = context.completedJobs.filter(
      (job) => `${job.scenarioId}:${JSON.stringify(job.parameter.location)}` === paramKey,
    );
    return this.groups.every((cat) =>
      sameParamJobs.some((job) =>
        job.groups.includes(cat) && job.finding?.vulnerable === true,
      ),
    );
  }

  async init(context: PluginContext): Promise<void> {
    this.commandBus = context.commandBus;
    context.commandBus.register(CreateAuditItemsCommand, async (cmd) => {
      return this.filterParameters(cmd.parameters).map((parameter) => ({
        signatureName: this.name,
        parameter,
        groups: this.groups,
      }));
    });

    context.commandBus.register(
      RunAuditCommand,
      this.name,
      async (cmd): Promise<AuditResult> => {
        if (this.isAlreadyChecked(cmd.context)) return { status: "skipped" };
        const finding = await this.runAudit(cmd.context);
        return { status: "completed", finding };
      },
    );
  }
}
