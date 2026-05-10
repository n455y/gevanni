import {
  Command,
  type CommandHandler,
  type PipelineHandler,
  type SingleCommand,
  type BroadcastCommand,
  type PipelineCommand,
} from "./command.ts";

type CommandResult<T> = T extends Command<infer R> ? R : never;

type HandlerFor<T extends Command<any>> = T extends PipelineCommand<any>
  ? PipelineHandler<T, CommandResult<T>>
  : CommandHandler<T, CommandResult<T>>;

interface CommandBus {
  register<T extends Command<any>>(
    commandClass: new (...args: any[]) => T,
    handler: HandlerFor<T>,
  ): void;

  dispatch<TResult>(command: SingleCommand<TResult>): Promise<TResult>;
  broadcast<TResult>(command: BroadcastCommand<TResult>): Promise<TResult[]>;
  pipe<TResult>(command: PipelineCommand<TResult>): Promise<TResult>;
}

type AnyHandler = CommandHandler<any, any> | PipelineHandler<any, any>;

class InMemoryCommandBus implements CommandBus {
  private singleHandlers = new Map<string, AnyHandler>();
  private multiHandlers = new Map<string, AnyHandler[]>();

  register<T extends Command<any>>(
    commandClass: new (...args: any[]) => T,
    handler: HandlerFor<T>,
  ): void {
    const key = commandClass.name;

    // Store as single handler (overwrites on re-register for dispatch)
    this.singleHandlers.set(key, handler);

    // Store as multi handler (appends on re-register for broadcast/pipe)
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
      accumulator = await (handler as PipelineHandler<typeof command, TResult>)(command, accumulator);
    }
    return accumulator;
  }
}

export { InMemoryCommandBus, type CommandBus };
