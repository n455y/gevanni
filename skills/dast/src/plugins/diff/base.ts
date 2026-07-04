import type { Exchange } from "../../types/models.ts";
import type { Plugin } from "../../core/plugin.ts";

export interface DiffResult {
  hasDifferent: boolean;
}

export interface DiffPlugin extends Plugin {
  compare(
    left: Exchange,
    right: Exchange,
    options?: Record<string, unknown>,
  ): DiffResult;
}
