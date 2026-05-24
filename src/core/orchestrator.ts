import crypto from "node:crypto";
import { ScanId, JobId, ErrorMessage, ReplayId } from "../types/branded.ts";
import type { SignatureGroupId } from "../types/branded.ts";
import type {
  Job,
  ScanState,
  Scenario,
  AuditParameter,
  Exchange,
  Finding,
  AuditMutation,
} from "../types/models.ts";
import { JobStatus, ScanStatus, ReplayResult } from "../types/models.ts";
import type { RuntimeContext } from "./runtime-context.ts";
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
  CreateProxyCommand,
} from "../commands/index.ts";

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
  context: RuntimeContext;
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
    const { commandBus, eventBus, logger } = this.deps.context;
    const id = ScanId(crypto.randomUUID());
    const now = new Date();
    const itemMap = new Map<string, AuditItem>();

    logger.info(`Loaded ${scenarios.length} scenarios`);

    // 1. Process each scenario
    const allJobs: Job[] = [];

    const planProxy = await commandBus.dispatch(new CreateProxyCommand([]));
    try {
      for (const scenario of scenarios) {
        logger.debug(`Processing scenario: ${scenario.name}`);

        // a. Save scenario for later retrieval during scan
        await commandBus.dispatch(new SaveScenarioCommand(scenario));

        // b. Dispatch ReplayCommand with empty mutations to get original request
        const rid = ReplayId(crypto.randomUUID());
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
            groups: item.groups,
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
    const { commandBus, eventBus, logger } = this.deps.context;
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
    let skippedCount = 0;

    // Track detected groups per parameter to enable group-based skipping
    const detectedGroups = new Map<string, Set<SignatureGroupId>>();

    // 3. Run jobs with concurrency
    await runWithConcurrency(jobs, concurrency, async (job: Job) => {
      try {
        // Check if any group for this parameter has already detected a vulnerability
        const paramKey = `${job.scenarioId}:${JSON.stringify(job.parameter.location)}`;
        if (job.groups.length > 0) {
          const detected = detectedGroups.get(paramKey);
          if (detected && job.groups.every((g) => detected.has(g))) {
            const skippedNow = new Date();
            await commandBus.dispatch(
              new UpdateJobCommand(job.id, {
                status: JobStatus.Skipped,
                error: ErrorMessage(
                  `Skipped: group already detected vulnerability for this parameter`,
                ),
                updatedAt: skippedNow,
              }),
            );
            eventBus.publish("scan:jobSkipped", { jobId: job.id });
            skippedCount++;
            return;
          }
        }

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
          const proxy = await commandBus.dispatch(
            new CreateProxyCommand(mutations),
          );
          try {
            const exchanges = await commandBus.dispatch(
              new ReplayCommand(scenario, {
                mutations,
                proxyPort: proxy.port,
                replayId: ReplayId(crypto.randomUUID()),
              }),
            );
            const [exchange, ...secondOrderExchanges] = exchanges;
            return new ReplayResult(exchange, secondOrderExchanges);
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

        // Mark groups as detected for this parameter
        if (finding.vulnerable && job.groups.length > 0) {
          const paramKey = `${job.scenarioId}:${JSON.stringify(job.parameter.location)}`;
          let detected = detectedGroups.get(paramKey);
          if (!detected) {
            detected = new Set();
            detectedGroups.set(paramKey, detected);
          }
          for (const group of job.groups) {
            detected.add(group);
          }
        }

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
      errorCount === jobs.length ? ScanStatus.Error : ScanStatus.Completed;

    await commandBus.dispatch(
      new SaveScanStateCommand({
        id: scanId,
        status: finalStatus,
        startedAt: now,
        updatedAt: new Date(),
      }),
    );

    logger.info(
      `Scan phase complete: ${completedCount} completed, ${skippedCount} skipped, ${errorCount} errors`,
    );
  }

  async report(scanId: ScanId): Promise<void> {
    const { commandBus, logger } = this.deps.context;

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
    const { commandBus, logger } = this.deps.context;

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
        groups: job.groups,
      });
    }

    // 4. Run scan phase
    await this.scan(sid, itemMap, concurrency ?? 5);
  }
}
