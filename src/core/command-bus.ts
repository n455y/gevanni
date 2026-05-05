import {
  type CommandHandler,
  type PipelineHandler,
  type SingleCommand,
  type BroadcastCommand,
  type PipelineCommand,
} from "./command.js";

interface CommandBus {
  register<T extends SingleCommand<TResult>, TResult>(
    commandClass: new (...args: any[]) => T,
    handler: CommandHandler<T, TResult>,
  ): void;
  register<T extends BroadcastCommand<TResult>, TResult>(
    commandClass: new (...args: any[]) => T,
    handler: CommandHandler<T, TResult>,
  ): void;
  register<T extends PipelineCommand<TAccumulator>, TAccumulator>(
    commandClass: new (...args: any[]) => T,
    handler: PipelineHandler<T, TAccumulator>,
  ): void;

  dispatch<TResult>(command: SingleCommand<TResult>): Promise<TResult>;
  broadcast<TResult>(command: BroadcastCommand<TResult>): Promise<TResult[]>;
  pipe<TResult>(command: PipelineCommand<TResult>): Promise<TResult>;
}

type AnyHandler = CommandHandler<any, any> | PipelineHandler<any, any>;

class InMemoryCommandBus implements CommandBus {
  private singleHandlers = new Map<string, AnyHandler>();
  private multiHandlers = new Map<string, AnyHandler[]>();

  register(
    commandClass: new (...args: any[]) => any,
    handler: AnyHandler,
  ): void {
    const key = commandClass.name;

    // Heuristic: if there is already a single handler for this key, overwrite it (SingleCommand semantics).
    // If there are multi handlers, append (BroadcastCommand/PipelineCommand semantics).
    // For the very first registration, we don't know yet, so we store as single.
    // The dispatch/broadcast/pipe methods will look in the correct map.
    // Actually, let's simplify: we store singles in singleHandlers and multis in multiHandlers.
    // Since we can't distinguish at register time which type of command it is from the class alone,
    // we'll use a unified approach: store in both maps and let the dispatch/broadcast/pipe methods
    // handle lookups.

    // Simpler approach: always store single handlers by key (overwrites), and multi handlers in arrays (appends).
    // The challenge is that register() is overloaded for all three command types.
    // We can't tell which kind of command class was passed in, so we need a different strategy.

    // Strategy: keep both maps. When register is called:
    // - If the key already has multi handlers, append to multi handlers.
    // - If the key already has a single handler, overwrite the single handler.
    // - If the key has neither, store as a single handler initially.
    //   But this won't work because broadcast/pipe commands need multi storage.

    // Better strategy: We determine the storage based on the existing entries.
    // If multi handlers exist for this key, we append.
    // Otherwise, we check if the command class extends BroadcastCommand or PipelineCommand
    // and store accordingly.

    // Simplest correct approach: store everything in multi-handlers array.
    // For SingleCommand dispatch: take the last registered handler (or first? last = overwrite semantics).
    // For BroadcastCommand/PipelineCommand: use all handlers.

    // Actually, the cleanest approach is to separate clearly:
    // - dispatch always looks in singleHandlers (Map of single handlers, overwritten on re-register)
    // - broadcast and pipe always look in multiHandlers (Map of arrays, appended on re-register)

    // The register method needs to know which kind of registration this is.
    // Since TypeScript overloads don't provide runtime info, we use a simple heuristic:
    // If the key already exists in multiHandlers, append there.
    // If the key already exists in singleHandlers, overwrite there.
    // For first registration, we can't know, so we store in both.
    // But that's wasteful.

    // Final approach: just use a single multi-handlers map for everything.
    // dispatch: uses the LAST handler registered (overwrite semantics achieved by always appending, then taking last)
    // broadcast/pipe: uses all handlers in order.
    // Wait, but dispatch should OVERWRITE, meaning only the latest handler runs.
    // If we always append, dispatch would need to take the last one. That works!

    // Let me re-read the spec:
    // - Single handlers stored in a Map keyed by constructor name -> overwrites on re-register
    // - Multi handlers (Broadcast + Pipeline) stored in a Map of arrays -> appends on re-register
    // - dispatch: looks up single handler, throws if not found
    // - broadcast: looks up multi handlers, runs all in parallel with Promise.all
    // - pipe: looks up multi handlers, runs sequentially

    // OK so we need TWO separate storage mechanisms. But register is a single method.
    // The key insight: we CAN determine the command type at registration time by checking
    // the prototype chain of the command class.

    // But actually, we don't need to. The spec says:
    // register() is overloaded for all three. In practice, the user will call register()
    // with the appropriate command class and handler, then use dispatch/broadcast/pipe
    // to execute. The execution method determines which storage to look up.

    // Since we can't know at register time, let's store in BOTH maps:
    // - singleHandlers: map of single handler (overwritten)
    // - multiHandlers: map of handler arrays (appended)
    // Then dispatch looks in singleHandlers, broadcast/pipe look in multiHandlers.

    // This means each register() call does both: overwrites single AND appends multi.
    // That's clean and correct.

    // Store as single handler (overwrites)
    this.singleHandlers.set(key, handler);

    // Store as multi handler (appends)
    const existing = this.multiHandlers.get(key);
    if (existing) {
      existing.push(handler);
    } else {
      this.multiHandlers.set(key, [handler]);
    }
  }

  async dispatch<TResult>(command: SingleCommand<TResult>): Promise<TResult> {
    const key = command.constructor.name;
    const handler = this.singleHandlers.get(key);
    if (!handler) {
      throw new Error(`No handler registered for command: ${key}`);
    }
    return (handler as CommandHandler<typeof command, TResult>)(command);
  }

  async broadcast<TResult>(command: BroadcastCommand<TResult>): Promise<TResult[]> {
    const key = command.constructor.name;
    const handlers = this.multiHandlers.get(key);
    if (!handlers || handlers.length === 0) {
      return [];
    }
    return Promise.all(
      handlers.map((handler) =>
        (handler as CommandHandler<typeof command, TResult>)(command),
      ),
    );
  }

  async pipe<TResult>(command: PipelineCommand<TResult>): Promise<TResult> {
    const key = command.constructor.name;
    const handlers = this.multiHandlers.get(key);
    if (!handlers || handlers.length === 0) {
      return command.initial;
    }
    let accumulator: TResult = command.initial;
    for (const handler of handlers) {
      accumulator = await (handler as any)(command, accumulator);
    }
    return accumulator;
  }
}

export { InMemoryCommandBus, type CommandBus };
