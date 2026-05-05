import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type {
  ScanId,
  JobId,
  RequestId,
  ScenarioId,
  ScenarioType,
  JobStatus,
  ScanStatus,
  IsoDateTime,
  TamperMethod,
  ErrorMessage,
} from "../types/branded.js";
import type {
  Job,
  ScanState,
  Scenario,
  InspectionParameter,
  HttpRequest,
  HttpResponse,
  Finding,
  TamperInstruction,
} from "../types/models.js";
import type { CommandBus } from "./command-bus.js";
import type { EventBus } from "./event-bus.js";
import type { Logger } from "./logger.js";
import type { SignatureInspector, ReplayFn } from "./inspector.js";
import {
  ReplayCommand,
  ParseRequestCommand,
  CreateInspectorsCommand,
  SaveJobCommand,
  LoadPendingJobsCommand,
  UpdateJobCommand,
  SaveScanStateCommand,
  LoadScanStateCommand,
  LoadScenarioCommand,
  LoadJobsByScanIdCommand,
  GenerateReportCommand,
} from "../commands/index.js";

// --- Branded type helpers ---

function scanId(value?: string): ScanId {
  return (value ?? crypto.randomUUID()) as ScanId;
}

function jobId(): JobId {
  return crypto.randomUUID() as JobId;
}

function requestId(): RequestId {
  return crypto.randomUUID() as RequestId;
}

function scenarioId(): ScenarioId {
  return crypto.randomUUID() as ScenarioId;
}

function isoNow(): IsoDateTime {
  return new Date().toISOString() as IsoDateTime;
}

// --- Load scenarios from Postman collections ---

interface PostmanItem {
  name: string;
  request: unknown;
  item?: PostmanItem[];
}

interface PostmanCollection {
  info?: { name?: string };
  item?: PostmanItem[];
}

function flattenItems(items: PostmanItem[]): PostmanItem[] {
  const result: PostmanItem[] = [];
  for (const item of items) {
    if (item.item && item.item.length > 0) {
      result.push(...flattenItems(item.item));
    } else if (item.request) {
      result.push(item);
    }
  }
  return result;
}

function loadScenarios(scenarioPaths: string[]): Scenario[] {
  const scenarios: Scenario[] = [];

  for (const scenarioPath of scenarioPaths) {
    const resolved = path.resolve(scenarioPath);

    let files: string[];
    try {
      const stat = fs.statSync(resolved);
      if (stat.isDirectory()) {
        files = fs
          .readdirSync(resolved)
          .filter((f) => f.endsWith(".json"))
          .map((f) => path.join(resolved, f));
      } else {
        files = [resolved];
      }
    } catch {
      continue;
    }

    for (const file of files) {
      try {
        const raw = fs.readFileSync(file, "utf-8");
        const collection = JSON.parse(raw) as PostmanCollection;
        const items = collection.item ?? [];
        const flatItems = flattenItems(items);

        for (const item of flatItems) {
          scenarios.push({
            id: scenarioId(),
            name: item.name ?? "unnamed",
            type: "postman" as ScenarioType,
            source: { item },
          });
        }
      } catch {
        // Skip invalid files
      }
    }
  }

  return scenarios;
}

// --- Worker pool ---

async function runWithConcurrency<T>(
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

interface OrchestratorDeps {
  commandBus: CommandBus;
  eventBus: EventBus;
  logger: Logger;
}

class Orchestrator {
  constructor(private deps: OrchestratorDeps) {}

  async plan(
    scenarioPaths: string[],
  ): Promise<{ scanId: ScanId; inspectors: Map<string, SignatureInspector> }> {
    const { commandBus, eventBus, logger } = this.deps;
    const id = scanId();
    const now = isoNow();
    const inspectorMap = new Map<string, SignatureInspector>();

    // 1. Load scenarios from paths
    const scenarios = loadScenarios(scenarioPaths);
    logger.info(`Loaded ${scenarios.length} scenarios`);

    // 2. Process each scenario
    const allJobs: Job[] = [];

    for (const scenario of scenarios) {
      logger.debug(`Processing scenario: ${scenario.name}`);

      // a. Dispatch ReplayCommand with empty instructions to get original request
      const replayResult: { request: HttpRequest; response: HttpResponse } =
        await commandBus.dispatch(new ReplayCommand(scenario, []));

      // b. Broadcast ParseRequestCommand to collect all InspectionParameters
      const parseResults: InspectionParameter[][] = await commandBus.broadcast(
        new ParseRequestCommand(replayResult.request),
      );
      const parameters: InspectionParameter[] = parseResults.flat();
      logger.debug(
        `Found ${parameters.length} inspection parameters for ${scenario.name}`,
      );

      // c. Broadcast CreateInspectorsCommand to collect all SignatureInspectors
      const inspectorResults: SignatureInspector[][] =
        await commandBus.broadcast(
          new CreateInspectorsCommand(parameters),
        );
      const inspectors: SignatureInspector[] = inspectorResults.flat();

      // d. For each inspector, create a Job
      for (const inspector of inspectors) {
        const jid = jobId();
        const rid = requestId();
        const job: Job = {
          id: jid,
          scenarioId: scenario.id,
          requestId: rid,
          signatureName: inspector.signatureName,
          parameters: inspector.parameters,
          status: "pending" as JobStatus,
          finding: null,
          error: null,
          createdAt: now,
          updatedAt: now,
        };

        allJobs.push(job);
        inspectorMap.set(jid, inspector);

        // Save job via storage
        await commandBus.dispatch(new SaveJobCommand(job));

        // Emit job created event
        eventBus.publish("plan:jobCreated", {
          jobId: jid,
          signatureName: inspector.signatureName,
          scenarioName: scenario.name,
        });
      }
    }

    // 3. Save scan state
    const scanState: ScanState = {
      id,
      status: "planning" as ScanStatus,
      startedAt: now,
      updatedAt: now,
    };
    await commandBus.dispatch(new SaveScanStateCommand(scanState));

    // 4. Emit events
    eventBus.publish("scan:started", { scanId: id });

    logger.info(`Plan phase complete: ${allJobs.length} jobs created for scan ${id}`);

    return { scanId: id, inspectors: inspectorMap };
  }

  async scan(
    scanId: ScanId,
    inspectors: Map<string, SignatureInspector>,
    concurrency: number,
  ): Promise<void> {
    const { commandBus, eventBus, logger } = this.deps;
    const now = isoNow();

    // 1. Update ScanState to "scanning"
    await commandBus.dispatch(
      new SaveScanStateCommand({
        id: scanId,
        status: "scanning" as ScanStatus,
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
            status: "running" as JobStatus,
            updatedAt: isoNow(),
          }),
        );
        eventBus.publish("scan:jobStarted", { jobId: job.id });

        // Get inspector
        const inspector = inspectors.get(job.id as string);
        if (!inspector) {
          throw new Error(`No inspector found for job ${job.id as string}`);
        }

        // Create replay function
        const replay: ReplayFn = async (
          instructions: TamperInstruction[],
        ) => {
          const scenario: Scenario = await commandBus.dispatch(
            new LoadScenarioCommand(job.scenarioId),
          );
          return commandBus.dispatch(
            new ReplayCommand(scenario, instructions),
          );
        };

        // Run inspection
        const finding = await inspector.inspect(replay);

        // Update job with finding
        const completedNow = isoNow();
        await commandBus.dispatch(
          new UpdateJobCommand(job.id, {
            status: "completed" as JobStatus,
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
        const errorMessage = (err instanceof Error ? err.message : String(err)) as ErrorMessage;
        const errorNow = isoNow();

        try {
          await commandBus.dispatch(
            new UpdateJobCommand(job.id, {
              status: "error" as JobStatus,
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
        ? ("error" as ScanStatus)
        : ("completed" as ScanStatus);

    await commandBus.dispatch(
      new SaveScanStateCommand({
        id: scanId,
        status: finalStatus,
        startedAt: now,
        updatedAt: isoNow(),
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
      logger.warn(`No scan state found for ${scanId as string}`);
      return;
    }

    // 2. Load all jobs
    const jobs: Job[] = await commandBus.dispatch(
      new LoadJobsByScanIdCommand(scanId),
    );

    // 3. Broadcast GenerateReportCommand
    await commandBus.broadcast(
      new GenerateReportCommand({ scanState, jobs }),
    );

    logger.info(`Report phase complete for scan ${scanId as string}`);
  }

  async resume(
    scanIdOrLatest?: ScanId,
    concurrency?: number,
  ): Promise<void> {
    const { commandBus, logger } = this.deps;

    // 1. Resolve scan ID
    let sid: ScanId;
    if (scanIdOrLatest) {
      sid = scanIdOrLatest;
    } else {
      const latestState: ScanState | null = await commandBus.dispatch(
        new LoadScanStateCommand("" as ScanId),
      );
      if (!latestState) {
        throw new Error("No incomplete scan found to resume");
      }
      sid = latestState.id;
    }

    logger.info(`Resuming scan ${sid as string}`);

    // 2. Load pending jobs
    const pendingJobs: Job[] = await commandBus.dispatch(
      new LoadPendingJobsCommand(sid),
    );

    if (pendingJobs.length === 0) {
      logger.info("No pending jobs to resume");
      return;
    }

    // 3. Reconstruct inspectors by collecting all parameters from pending jobs
    const allParameters: InspectionParameter[] = [];
    for (const job of pendingJobs) {
      allParameters.push(...job.parameters);
    }

    // Deduplicate parameters by comparing signatureName + parameters
    const inspectorResults: SignatureInspector[][] =
      await commandBus.broadcast(
        new CreateInspectorsCommand(allParameters),
      );
    const allInspectors: SignatureInspector[] = inspectorResults.flat();

    // 4. Match inspectors to jobs
    const inspectorMap = new Map<string, SignatureInspector>();

    for (const job of pendingJobs) {
      const matched = allInspectors.find(
        (insp) =>
          insp.signatureName === job.signatureName &&
          insp.parameters.length === job.parameters.length &&
          insp.parameters.every(
            (p, i) =>
              p.type === job.parameters[i].type &&
              JSON.stringify(p.location) ===
                JSON.stringify(job.parameters[i].location),
          ),
      );

      if (matched) {
        inspectorMap.set(job.id as string, matched);
      }
    }

    // 5. Run scan phase
    await this.scan(sid, inspectorMap, concurrency ?? 5);
  }
}

export { Orchestrator, type OrchestratorDeps, loadScenarios, runWithConcurrency };
