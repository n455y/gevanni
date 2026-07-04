import { promises as fs } from "node:fs";
import { join } from "node:path";
import type { StoragePlugin, PluginContext } from "../../core/plugin.ts";
import type { CommandBus } from "../../core/command-bus.ts";
import type { ReplayId } from "../../types/branded.ts";
import {
  serializeSignatureJob,
  deserializeSignatureJob,
  serializeScanState,
  deserializeScanState,
  type ScanState,
  type Scenario,
  type Exchange,
  type SerializedSignatureJob,
  type SerializedScanState,
} from "../../types/models.ts";
import { ScanId } from "../../types/branded.ts";
import {
  SaveJobCommand,
  LoadJobCommand,
  LoadJobsByStatusCommand,
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

function reviveBuffer(body: unknown): Buffer | null {
  if (body == null) return null;
  if (Buffer.isBuffer(body)) return body;
  if (
    typeof body === "object" &&
    "type" in body &&
    (body as { type: string }).type === "Buffer" &&
    "data" in body &&
    Array.isArray((body as { data: unknown }).data)
  ) {
    return Buffer.from((body as { data: number[] }).data);
  }
  return Buffer.from(String(body));
}

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

export interface JsonStorageConfig {
  outputDir?: string;
}

export default class JsonStoragePlugin implements StoragePlugin {
  readonly name = "storage:json";
  private outputDir: string;
  private fileLocks = new Map<string, Promise<void>>();

  constructor(options: JsonStorageConfig = {}) {
    this.outputDir = options.outputDir ?? "./gevanni-results";
  }

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
    const bus: CommandBus = context.commandBus;

    const scanDir = (scanId: ScanId) => join(this.outputDir, scanId);
    const jobsPath = (scanId: ScanId) => join(scanDir(scanId), "jobs.json");
    const statePath = (scanId: ScanId) => join(scanDir(scanId), "state.json");
    const scenarioPath = (scanId: ScanId) =>
      join(scanDir(scanId), "scenario.json");

    // --- SaveJobCommand ---
    bus.register(SaveJobCommand, async (cmd) => {
      const path = jobsPath(cmd.job.scanId);
      await this.withFileLock(path, async () => {
        const jobs: SerializedSignatureJob[] = (await readJsonFile<SerializedSignatureJob[]>(path)) ?? [];
        jobs.push(serializeSignatureJob(cmd.job));
        await writeJsonFile(path, jobs);
      });
    });

    // --- LoadJobCommand ---
    bus.register(LoadJobCommand, async (cmd) => {
      const entries = await fs.readdir(this.outputDir, {
        withFileTypes: true,
      });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const path = join(this.outputDir, entry.name, "jobs.json");
        const jobs = await readJsonFile<SerializedSignatureJob[]>(path);
        if (jobs) {
          const match = jobs.find((j) => j.id === cmd.id);
          if (match) return deserializeSignatureJob(match);
        }
      }
      return null;
    });

    // --- LoadJobsByStatusCommand ---
    bus.register(LoadJobsByStatusCommand, async (cmd) => {
      const path = jobsPath(cmd.scanId);
      const jobs = await readJsonFile<SerializedSignatureJob[]>(path);
      if (!jobs) return [];
      const all = jobs.map(deserializeSignatureJob);
      if (cmd.statusFilter.length === 0) return all;
      return all.filter((j) => cmd.statusFilter.includes(j.status));
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
            const jobs = await readJsonFile<SerializedSignatureJob[]>(filePath);
            if (!jobs) return;
            const idx = jobs.findIndex((j) => j.id === cmd.id);
            if (idx !== -1) {
              const { parameter: _, updatedAt, createdAt, ...rest } = cmd.updates;
              jobs[idx] = {
                ...jobs[idx],
                ...rest,
                ...(updatedAt != null ? { updatedAt: updatedAt.getTime() } : {}),
                ...(createdAt != null ? { createdAt: createdAt.getTime() } : {}),
                id: jobs[idx].id,
              };
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
      await writeJsonFile(statePath(cmd.state.id), serializeScanState(cmd.state));
    });

    // --- LoadScanStateCommand ---
    bus.register(LoadScanStateCommand, async (cmd) => {
      if (cmd.id) {
        const data = await readJsonFile<SerializedScanState>(statePath(cmd.id));
        return data ? deserializeScanState(data) : null;
      }

      try {
        const entries = await fs.readdir(this.outputDir, {
          withFileTypes: true,
        });
        let latest: ScanState | null = null;
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          const data = await readJsonFile<SerializedScanState>(
            join(this.outputDir, entry.name, "state.json"),
          );
          if (data) {
            const state = deserializeScanState(data);
            if (
              state.status !== ("completed" as ScanState["status"])
            ) {
              if (!latest || state.updatedAt > latest.updatedAt) {
                latest = state;
              }
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
      await writeJsonFile(scenarioPath(ScanId(cmd.scenario.id as string)), cmd.scenario);
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
    const exchangesPath = (replayId: ReplayId) =>
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
      const exchanges = (await readJsonFile<Exchange[]>(path)) ?? [];
      return exchanges.map((e) => ({
        ...e,
        request: {
          ...e.request,
          body: reviveBuffer(e.request.body),
        },
        response: {
          ...e.response,
          body: reviveBuffer(e.response.body),
        },
      }));
    });

    // Ensure base output directory exists
    await ensureDir(this.outputDir);
  }
}
