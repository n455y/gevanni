import {
  Command,
  PartitionedSingleCommand,
  PartitionedBroadcastCommand,
  PartitionedPipelineCommand,
  type CommandHandler,
  type PipelineHandler,
  type SingleCommand,
  type BroadcastCommand,
  type PipelineCommand,
} from "./command.ts";

type AnyPartitioned<TResult = any> =
  | PartitionedSingleCommand<TResult>
  | PartitionedBroadcastCommand<TResult>
  | PartitionedPipelineCommand<TResult>;

type CommandResult<T> = T extends Command<infer R> ? R : never;

type HandlerFor<T extends Command<any>> = T extends PipelineCommand<any>
  ? PipelineHandler<T, CommandResult<T>>
  : CommandHandler<T, CommandResult<T>>;

const isPartitioned = (cmd: Command<any>): cmd is AnyPartitioned =>
  cmd instanceof PartitionedSingleCommand ||
  cmd instanceof PartitionedBroadcastCommand ||
  cmd instanceof PartitionedPipelineCommand;

export interface CommandBus {
  register<T extends Command<any>>(
    commandClass: new (...args: any[]) => T,
    ...args: T extends AnyPartitioned
      ? [key: string, handler: HandlerFor<T>]
      : [handler: HandlerFor<T>]
  ): void;

  dispatch<TResult>(command: SingleCommand<TResult>): Promise<TResult>;
  broadcast<TResult>(command: BroadcastCommand<TResult>): Promise<TResult[]>;
  pipe<TResult>(command: PipelineCommand<TResult>): Promise<TResult>;
}

type AnyHandler = CommandHandler<any, any> | PipelineHandler<any, any>;

export class InMemoryCommandBus implements CommandBus {
  private handlers = new Map<string, AnyHandler[]>();
  private keyedHandlers = new Map<string, Map<string, AnyHandler[]>>();

  register<T extends Command<any>>(
    commandClass: new (...args: any[]) => T,
    ...args: T extends AnyPartitioned
      ? [key: string, handler: HandlerFor<T>]
      : [handler: HandlerFor<T>]
  ): void;
  register<T extends Command<any>>(
    commandClass: new (...args: any[]) => T,
    keyOrHandler: string | HandlerFor<T>,
    handler?: HandlerFor<T>,
  ): void {
    const name = commandClass.name;

    if (typeof keyOrHandler === "string" && handler) {
      let keyMap = this.keyedHandlers.get(name);
      if (!keyMap) {
        keyMap = new Map();
        this.keyedHandlers.set(name, keyMap);
      }
      const existing = keyMap.get(keyOrHandler);
      if (existing) {
        existing.push(handler);
      } else {
        keyMap.set(keyOrHandler, [handler]);
      }
      return;
    }

    const h = keyOrHandler as HandlerFor<T>;
    const existing = this.handlers.get(name);
    if (existing) {
      existing.push(h);
    } else {
      this.handlers.set(name, [h]);
    }
  }

  private resolveHandlers(command: Command<any>): AnyHandler[] {
    const name = command.constructor.name;
    if (isPartitioned(command)) {
      return this.keyedHandlers.get(name)?.get(command.partition) ?? [];
    }
    return this.handlers.get(name) ?? [];
  }

  async dispatch<TResult>(command: SingleCommand<TResult>): Promise<TResult> {
    const handlers = this.resolveHandlers(command);
    if (handlers.length === 0) {
      const name = command.constructor.name;
      const suffix = isPartitioned(command) ? ` with partition: ${command.partition}` : "";
      throw new Error(`No handler registered for command: ${name}${suffix}`);
    }
    return (handlers[handlers.length - 1] as CommandHandler<typeof command, TResult>)(command);
  }

  async broadcast<TResult>(command: BroadcastCommand<TResult>): Promise<TResult[]> {
    const handlers = this.resolveHandlers(command);
    return Promise.all(
      handlers.map((h) => (h as CommandHandler<typeof command, TResult>)(command)),
    );
  }

  async pipe<TResult>(command: PipelineCommand<TResult>): Promise<TResult> {
    const handlers = this.resolveHandlers(command);
    let accumulator: TResult = command.initial;
    for (const handler of handlers) {
      accumulator = await (handler as PipelineHandler<typeof command, TResult>)(command, accumulator);
    }
    return accumulator;
  }
}
