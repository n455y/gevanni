import { promises as fs } from "node:fs";
import { join } from "node:path";
import type { Plugin, PluginContext } from "../../core/plugin.ts";
import type { CommandBus } from "../../core/command-bus.ts";
import type { Job, ScanState, Scenario, Exchange } from "../../types/models.ts";
import type { ScanId, JobStatus } from "../../types/branded.ts";
import {
  SaveJobCommand,
  LoadJobCommand,
  LoadJobsByScanIdCommand,
  LoadPendingJobsCommand,
  UpdateJobCommand,
  SaveScanStateCommand,
  LoadScanStateCommand,
  SaveScenarioCommand,
  LoadScenarioCommand,
} from "../../commands/storage.ts";
import {
  SaveExchangeCommand,
  LoadExchangesCommand,
} from "../../commands/exchange.ts";

// --- Helpers ---

async function ensureDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
}

async function readJsonFile<T>(path: string): Promise<T | null> {
  try {
    const raw = await fs.readFile(path, "utf-8");
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

async function writeJsonFile(path: string, data: unknown): Promise<void> {
  const dir = join(path, "..");
  await ensureDir(dir);
  await fs.writeFile(path, JSON.stringify(data, null, 2), "utf-8");
}

// --- Plugin ---

interface JsonStorageConfig {
  outputDir?: string;
}

class JsonStoragePlugin implements Plugin {
  readonly name = "json-storage";
  private outputDir = "./gevanni-results";
  private fileLocks = new Map<string, Promise<void>>();

  private async withFileLock<T>(filePath: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.fileLocks.get(filePath);
    let resolve!: () => void;
    const next = new Promise<void>((r) => { resolve = r; });
    this.fileLocks.set(filePath, next);
    if (prev) await prev.catch(() => {});
    try {
      return await fn();
    } finally {
      resolve();
      if (this.fileLocks.get(filePath) === next) {
        this.fileLocks.delete(filePath);
      }
    }
  }

  async init(context: PluginContext): Promise<void> {
    const cfg = context.config as JsonStorageConfig;
    this.outputDir = cfg.outputDir ?? "./gevanni-results";
    const bus: CommandBus = context.commandBus;

    const scanDir = (scanId: ScanId) => join(this.outputDir, scanId);
    const jobsPath = (scanId: ScanId) => join(scanDir(scanId), "jobs.json");
    const statePath = (scanId: ScanId) => join(scanDir(scanId), "state.json");
    const scenarioPath = (scanId: ScanId) =>
      join(scanDir(scanId), "scenario.json");

    // --- SaveJobCommand ---
    bus.register(SaveJobCommand, async (cmd) => {
      const path = jobsPath(cmd.job.scenarioId as unknown as ScanId);
      await this.withFileLock(path, async () => {
        const jobs: Job[] = (await readJsonFile<Job[]>(path)) ?? [];
        jobs.push(cmd.job);
        await writeJsonFile(path, jobs);
      });
    });

    // --- LoadJobCommand ---
    bus.register(LoadJobCommand, async (cmd) => {
      let found: Job | null = null;

      try {
        const entries = await fs.readdir(this.outputDir, {
          withFileTypes: true,
        });
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          const path = join(this.outputDir, entry.name, "jobs.json");
          const jobs = await readJsonFile<Job[]>(path);
          if (jobs) {
            found = jobs.find((j) => j.id === cmd.id) ?? null;
            if (found) break;
          }
        }
      } catch {
        // outputDir may not exist yet
      }

      return found;
    });

    // --- LoadJobsByScanIdCommand ---
    bus.register(LoadJobsByScanIdCommand, async (cmd) => {
      const allJobs: Job[] = [];
      try {
        const entries = await fs.readdir(this.outputDir, {
          withFileTypes: true,
        });
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          const path = join(this.outputDir, entry.name, "jobs.json");
          const jobs = await readJsonFile<Job[]>(path);
          if (jobs) {
            allJobs.push(...jobs.filter((j) => j.scanId === cmd.scanId));
          }
        }
      } catch {
        // outputDir may not exist yet
      }
      return allJobs;
    });

    // --- LoadPendingJobsCommand ---
    bus.register(LoadPendingJobsCommand, async (cmd) => {
      const allJobs: Job[] = [];
      try {
        const entries = await fs.readdir(this.outputDir, {
          withFileTypes: true,
        });
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          const path = join(this.outputDir, entry.name, "jobs.json");
          const jobs = await readJsonFile<Job[]>(path);
          if (jobs) {
            allJobs.push(...jobs);
          }
        }
      } catch {
        // outputDir may not exist yet
      }
      return allJobs.filter(
        (j) => j.status === ("pending" as JobStatus) && j.scanId === cmd.scanId,
      );
    });

    // --- UpdateJobCommand ---
    bus.register(UpdateJobCommand, async (cmd) => {
      let updated = false;

      try {
        const entries = await fs.readdir(this.outputDir, {
          withFileTypes: true,
        });
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          const filePath = join(this.outputDir, entry.name, "jobs.json");
          await this.withFileLock(filePath, async () => {
            const jobs = await readJsonFile<Job[]>(filePath);
            if (!jobs) return;
            const idx = jobs.findIndex((j) => j.id === cmd.id);
            if (idx !== -1) {
              jobs[idx] = { ...jobs[idx], ...cmd.updates, id: jobs[idx].id };
              await writeJsonFile(filePath, jobs);
              updated = true;
            }
          });
          if (updated) break;
        }
      } catch {
        // outputDir may not exist yet
      }

      if (!updated) {
        throw new Error(`Job not found: ${cmd.id as string}`);
      }
    });

    // --- SaveScanStateCommand ---
    bus.register(SaveScanStateCommand, async (cmd) => {
      await writeJsonFile(statePath(cmd.state.id), cmd.state);
    });

    // --- LoadScanStateCommand ---
    bus.register(LoadScanStateCommand, async (cmd) => {
      if (cmd.id) {
        return readJsonFile<ScanState>(statePath(cmd.id));
      }

      try {
        const entries = await fs.readdir(this.outputDir, {
          withFileTypes: true,
        });
        let latest: ScanState | null = null;
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          const state = await readJsonFile<ScanState>(
            join(this.outputDir, entry.name, "state.json"),
          );
          if (
            state &&
            state.status !== ("completed" as ScanState["status"])
          ) {
            if (!latest || state.updatedAt > latest.updatedAt) {
              latest = state;
            }
          }
        }
        return latest;
      } catch {
        return null;
      }
    });

    // --- SaveScenarioCommand ---
    bus.register(SaveScenarioCommand, async (cmd) => {
      await writeJsonFile(scenarioPath(cmd.scenario.id as unknown as ScanId), cmd.scenario);
    });

    // --- LoadScenarioCommand ---
    bus.register(LoadScenarioCommand, async (cmd) => {
      try {
        const entries = await fs.readdir(this.outputDir, {
          withFileTypes: true,
        });
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          const scenario = await readJsonFile<Scenario>(
            join(this.outputDir, entry.name, "scenario.json"),
          );
          if (scenario && scenario.id === cmd.id) {
            return scenario;
          }
        }
      } catch {
        // outputDir may not exist yet
      }

      throw new Error(`Scenario not found: ${cmd.id as string}`);
    });

    // --- Exchange storage ---
    const exchangesPath = (replayId: string) =>
      join(this.outputDir, "exchanges", `${replayId}.json`);

    bus.register(SaveExchangeCommand, async (cmd) => {
      const path = exchangesPath(cmd.replayId);
      await this.withFileLock(path, async () => {
        const exchanges: Exchange[] =
          (await readJsonFile<Exchange[]>(path)) ?? [];
        exchanges.push(cmd.exchange);
        await writeJsonFile(path, exchanges);
      });
    });

    bus.register(LoadExchangesCommand, async (cmd) => {
      const path = exchangesPath(cmd.replayId);
      return (await readJsonFile<Exchange[]>(path)) ?? [];
    });

    // Ensure base output directory exists
    await ensureDir(this.outputDir);
  }
}

export { JsonStoragePlugin };
