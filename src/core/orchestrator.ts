import crypto from "node:crypto";
import {
  ScanId,
  JobId,
  JobStatus,
  ScanStatus,
  ErrorMessage,
} from "../types/branded.ts";
import type {
  Job,
  ScanState,
  Scenario,
  AuditParameter,
  Exchange,
  Finding,
  AuditMutation,
} from "../types/models.ts";
import type { CommandBus } from "./command-bus.ts";
import type { EventBus } from "./event-bus.ts";
import type { Logger } from "./logger.ts";
import type { AuditItem } from "./audit-item.ts";
import {
  ReplayCommand,
  ParseRequestCommand,
  CreateAuditItemsCommand,
  RunAuditCommand,
  SaveJobCommand,
  LoadPendingJobsCommand,
  UpdateJobCommand,
  SaveScanStateCommand,
  LoadScanStateCommand,
  LoadScenarioCommand,
  SaveScenarioCommand,
  LoadJobsByScanIdCommand,
  GenerateReportCommand,
} from "../commands/index.ts";
import { startMutationProxy } from "../plugins/proxy/http-proxy.ts";

// --- Worker pool ---

export async function runWithConcurrency<T>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  const queue = [...items];
  const workers = Array.from(
    { length: Math.min(concurrency, queue.length) },
    async () => {
      while (queue.length > 0) {
        const item = queue.shift();
        if (item) await fn(item);
      }
    },
  );
  await Promise.all(workers);
}

// --- Orchestrator ---

export interface OrchestratorDeps {
  commandBus: CommandBus;
  eventBus: EventBus;
  logger: Logger;
}

export class Orchestrator {
  private deps: OrchestratorDeps;
  constructor(deps: OrchestratorDeps) {
    this.deps = deps;
  }

  async plan(scenarios: Scenario[]): Promise<{
    scanId: ScanId;
    items: Map<string, AuditItem>;
  }> {
    const { commandBus, eventBus, logger } = this.deps;
    const id = ScanId(crypto.randomUUID());
    const now = new Date();
    const itemMap = new Map<string, AuditItem>();

    logger.info(`Loaded ${scenarios.length} scenarios`);

    // 1. Process each scenario
    const allJobs: Job[] = [];

    const planProxy = await startMutationProxy([], commandBus);
    try {
      for (const scenario of scenarios) {
        logger.debug(`Processing scenario: ${scenario.name}`);

        // a. Save scenario for later retrieval during scan
        await commandBus.dispatch(new SaveScenarioCommand(scenario));

        // b. Dispatch ReplayCommand with empty mutations to get original request
        const rid = crypto.randomUUID();
        const replayResult = (
          (await commandBus.dispatch(
            new ReplayCommand(scenario, {
              mutations: [],
              proxyPort: planProxy.port,
              replayId: rid,
            }),
          )) as Exchange[]
        )[0];

        // b. Broadcast ParseRequestCommand to collect all AuditParameters
        const parseResults: AuditParameter[][] = await commandBus.broadcast(
          new ParseRequestCommand(replayResult.request),
        );
        const parameters: AuditParameter[] = parseResults.flat();
        logger.debug(
          `Found ${parameters.length} audit parameters for ${scenario.name}`,
        );

        // c. Broadcast CreateAuditItemsCommand to collect all AuditItems
        const definitionResults: AuditItem[][] = await commandBus.broadcast(
          new CreateAuditItemsCommand(parameters),
        );
        const items: AuditItem[] = definitionResults.flat();

        // d. For each definition, create a Job
        for (const item of items) {
          const jid = JobId(crypto.randomUUID());
          const job: Job = {
            id: jid,
            scanId: id,
            scenarioId: scenario.id,
            signatureName: item.signatureName,
            parameter: item.parameter,
            status: JobStatus.Pending,
            finding: null,
            error: null,
            createdAt: now,
            updatedAt: now,
          };

          allJobs.push(job);
          itemMap.set(jid, item);

          // Save job via storage
          await commandBus.dispatch(new SaveJobCommand(job));

          // Emit job created event
          eventBus.publish("plan:jobCreated", {
            jobId: jid,
            signatureName: item.signatureName,
            scenarioName: scenario.name,
          });
        }
      }
    } finally {
      planProxy.close();
    }

    // 2. Save scan state
    const scanState: ScanState = {
      id,
      status: ScanStatus.Planning,
      startedAt: now,
      updatedAt: now,
    };
    await commandBus.dispatch(new SaveScanStateCommand(scanState));

    // 3. Emit events
    eventBus.publish("scan:started", { scanId: id });

    logger.info(
      `Plan phase complete: ${allJobs.length} jobs created for scan ${id}`,
    );

    return { scanId: id, items: itemMap };
  }

  async scan(
    scanId: ScanId,
    items: Map<string, AuditItem>,
    concurrency: number,
  ): Promise<void> {
    const { commandBus, eventBus, logger } = this.deps;
    const now = new Date();

    // 1. Update ScanState to "scanning"
    await commandBus.dispatch(
      new SaveScanStateCommand({
        id: scanId,
        status: ScanStatus.Scanning,
        startedAt: now,
        updatedAt: now,
      }),
    );

    // 2. Load pending jobs
    const jobs: Job[] = await commandBus.dispatch(
      new LoadPendingJobsCommand(scanId),
    );

    if (jobs.length === 0) {
      logger.info("No pending jobs to scan");
      return;
    }

    logger.info(
      `Starting scan phase: ${jobs.length} jobs with concurrency ${concurrency}`,
    );

    let completedCount = 0;
    let errorCount = 0;

    // 3. Run jobs with concurrency
    await runWithConcurrency(jobs, concurrency, async (job: Job) => {
      try {
        // Update job status to running
        await commandBus.dispatch(
          new UpdateJobCommand(job.id, {
            status: JobStatus.Running,
            updatedAt: new Date(),
          }),
        );
        eventBus.publish("scan:jobStarted", { jobId: job.id });

        // Get audit item
        const item = items.get(job.id);
        if (!item) {
          throw new Error(`No audit item found for job ${job.id}`);
        }

        // Create replay function
        const replay = async (mutations: AuditMutation[]) => {
          const scenario: Scenario = await commandBus.dispatch(
            new LoadScenarioCommand(job.scenarioId),
          );
          const proxy = await startMutationProxy(mutations, commandBus);
          try {
            const [exchange] = await commandBus.dispatch(
              new ReplayCommand(scenario, {
                mutations,
                proxyPort: proxy.port,
                replayId: job.id,
              }),
            );
            return exchange;
          } finally {
            proxy.close();
          }
        };

        // Run audit
        const results = await commandBus.broadcast(
          new RunAuditCommand({
            signatureName: item.signatureName,
            parameter: job.parameter,
            replay,
          }),
        );
        const finding = results.find((r): r is Finding => r !== null);
        if (!finding) {
          throw new Error(`No handler for signature: ${item.signatureName}`);
        }

        // Update job with finding
        const completedNow = new Date();
        await commandBus.dispatch(
          new UpdateJobCommand(job.id, {
            status: JobStatus.Completed,
            finding,
            updatedAt: completedNow,
          }),
        );
        eventBus.publish("scan:jobCompleted", {
          jobId: job.id,
          finding,
        });

        completedCount++;
      } catch (err) {
        const errorMessage = ErrorMessage(
          err instanceof Error ? err.message : String(err),
        );
        const errorNow = new Date();

        try {
          await commandBus.dispatch(
            new UpdateJobCommand(job.id, {
              status: JobStatus.Error,
              error: errorMessage,
              updatedAt: errorNow,
            }),
          );
        } catch {
          // Job update itself failed; log but don't crash
        }

        eventBus.publish("scan:jobError", {
          jobId: job.id,
          error: errorMessage,
        });

        errorCount++;
      }
    });

    // 4. Update final scan state
    const finalStatus: ScanStatus =
      errorCount === jobs.length
        ? ScanStatus.Error
        : ScanStatus.Completed;

    await commandBus.dispatch(
      new SaveScanStateCommand({
        id: scanId,
        status: finalStatus,
        startedAt: now,
        updatedAt: new Date(),
      }),
    );

    logger.info(
      `Scan phase complete: ${completedCount} completed, ${errorCount} errors`,
    );
  }

  async report(scanId: ScanId): Promise<void> {
    const { commandBus, logger } = this.deps;

    // 1. Load scan state
    const scanState: ScanState | null = await commandBus.dispatch(
      new LoadScanStateCommand(scanId),
    );

    if (!scanState) {
      logger.warn(`No scan state found for ${scanId}`);
      return;
    }

    // 2. Load all jobs
    const jobs: Job[] = await commandBus.dispatch(
      new LoadJobsByScanIdCommand(scanId),
    );

    // 3. Broadcast GenerateReportCommand
    await commandBus.broadcast(new GenerateReportCommand({ scanState, jobs }));

    logger.info(`Report phase complete for scan ${scanId}`);
  }

  async resume(scanIdOrLatest?: ScanId, concurrency?: number): Promise<void> {
    const { commandBus, logger } = this.deps;

    // 1. Resolve scan ID
    let sid: ScanId;
    if (scanIdOrLatest) {
      sid = scanIdOrLatest;
    } else {
      const latestState: ScanState | null = await commandBus.dispatch(
        new LoadScanStateCommand(ScanId("")),
      );
      if (!latestState) {
        throw new Error("No incomplete scan found to resume");
      }
      sid = latestState.id;
    }

    logger.info(`Resuming scan ${sid}`);

    // 2. Load pending jobs
    const pendingJobs: Job[] = await commandBus.dispatch(
      new LoadPendingJobsCommand(sid),
    );

    if (pendingJobs.length === 0) {
      logger.info("No pending jobs to resume");
      return;
    }

    // 3. Build item map from pending jobs
    const itemMap = new Map<string, AuditItem>();

    for (const job of pendingJobs) {
      itemMap.set(job.id, {
        signatureName: job.signatureName,
        parameter: job.parameter,
      });
    }

    // 4. Run scan phase
    await this.scan(sid, itemMap, concurrency ?? 5);
  }
}
