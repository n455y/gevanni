import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/index.ts";
import type { AuditResult } from "../../commands/run-audit.ts";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import type { AuditParameter, Finding } from "../../types/models.ts";
import { type SignatureId, SignatureGroupId } from "../../types/branded.ts";

export interface SignaturePlugin extends Plugin {
  readonly name: SignatureId;
}

export abstract class SignaturePluginBase implements SignaturePlugin {
  private static readonly _categories = new Map<SignatureId, SignatureGroupId[]>();

  static resetCategories(): void {
    SignaturePluginBase._categories.clear();
  }

  abstract readonly name: SignatureId;

  protected get categories(): SignatureGroupId[] {
    return [SignatureGroupId(this.name as string)];
  }

  protected abstract runAudit(context: RunAuditContext): Promise<Finding>;

  protected filterParameters(parameters: AuditParameter[]) {
    return parameters;
  }

  protected isAlreadyChecked(context: RunAuditContext): boolean {
    const paramKey = `${context.scenarioId}:${JSON.stringify(context.parameter.location)}`;
    const sameParamJobs = context.completedJobs.filter(
      (job) => `${job.scenarioId}:${JSON.stringify(job.parameter.location)}` === paramKey,
    );
    return this.categories.every((cat) =>
      sameParamJobs.some((job) => {
        const jobCategories = SignaturePluginBase._categories.get(job.signatureName);
        return jobCategories?.includes(cat) && job.finding?.vulnerable === true;
      }),
    );
  }

  async init(context: PluginContext): Promise<void> {
    SignaturePluginBase._categories.set(this.name, this.categories);

    context.commandBus.register(CreateAuditItemsCommand, async (cmd) => {
      return this.filterParameters(cmd.parameters).map((parameter) => ({
        signatureName: this.name,
        parameter,
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
