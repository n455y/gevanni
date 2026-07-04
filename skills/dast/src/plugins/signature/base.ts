import { CreateAuditItemsCommand } from "../../commands/create-audit-items.ts";
import { RunAuditCommand } from "../../commands/index.ts";
import type { AuditResult } from "../../commands/run-audit.ts";
import type { CommandBus } from "../../core/command-bus.ts";
import type { SignaturePlugin, PluginContext, PluginRegistry } from "../../core/plugin.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import type { AuditParameter, DiffStrategyConfig, Exchange, Finding } from "../../types/models.ts";
import type { SignatureGroupId } from "../../types/branded.ts";
import type { DiffPlugin, DiffResult } from "../diff/base.ts";

export type { SignaturePlugin };

export abstract class SignaturePluginBase implements SignaturePlugin {
  abstract readonly name: `signature:${string}`;
  protected abstract readonly groups: SignatureGroupId[];
  protected commandBus!: CommandBus;
  protected pluginRegistry?: PluginRegistry;

  protected abstract runAudit(context: RunAuditContext): Promise<Finding>;

  protected filterParameters(parameters: AuditParameter[]) {
    return parameters;
  }

  protected isAlreadyChecked(context: RunAuditContext): boolean {
    const paramKey = `${context.scenario.id}:${JSON.stringify(context.parameter.location)}`;
    const sameParamJobs = context.completedJobs.filter(
      (job) =>
        `${job.scenarioId}:${JSON.stringify(job.parameter.location)}` ===
        paramKey,
    );
    return this.groups.every((cat) =>
      sameParamJobs.some(
        (job) => job.groups.includes(cat) && job.finding?.vulnerable === true,
      ),
    );
  }

  protected compareDiff(
    left: Exchange,
    right: Exchange,
    config: DiffStrategyConfig,
  ): DiffResult {
    if (!this.pluginRegistry) {
      throw new Error(
        `${this.name}: pluginRegistry is not available (expected to be set via PluginContext)`,
      );
    }
    const plugin = this.pluginRegistry.getByName<DiffPlugin>(
      `diff:${config.type}`,
    );
    if (!plugin) {
      throw new Error(
        `${this.name}: unknown diff strategy "${config.type}". Known: exact, json, html`,
      );
    }
    return plugin.compare(left, right, config.options);
  }

  async init(context: PluginContext): Promise<void> {
    this.commandBus = context.commandBus;
    this.pluginRegistry = context.pluginRegistry;
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
