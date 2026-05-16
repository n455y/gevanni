import {
  Command,
  KeyedBroadcastCommand,
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

export interface CommandBus {
  register<T extends Command<any>>(
    commandClass: new (...args: any[]) => T,
    ...args: T extends KeyedBroadcastCommand<any>
      ? [key: string, handler: CommandHandler<T, CommandResult<T>>]
      : [handler: HandlerFor<T>]
  ): void;

  dispatch<TResult>(command: SingleCommand<TResult>): Promise<TResult>;
  broadcast<TResult>(command: BroadcastCommand<TResult>): Promise<TResult[]>;
  pipe<TResult>(command: PipelineCommand<TResult>): Promise<TResult>;
}

type AnyHandler = CommandHandler<any, any> | PipelineHandler<any, any>;

export class InMemoryCommandBus implements CommandBus {
  private singleHandlers = new Map<string, AnyHandler>();
  private multiHandlers = new Map<string, AnyHandler[]>();
  private keyedHandlers = new Map<string, Map<string, AnyHandler[]>>();

  register<T extends Command<any>>(
    commandClass: new (...args: any[]) => T,
    ...args: T extends KeyedBroadcastCommand<any>
      ? [key: string, handler: CommandHandler<T, CommandResult<T>>]
      : [handler: HandlerFor<T>]
  ): void;
  register<T extends Command<any>>(
    commandClass: new (...args: any[]) => T,
    keyOrHandler: string | HandlerFor<T>,
    handler?: CommandHandler<T, CommandResult<T>>,
  ): void {
    const name = commandClass.name;

    if (typeof keyOrHandler === "string" && handler) {
      this.singleHandlers.set(name, handler);
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
    this.singleHandlers.set(name, h);
    const existing = this.multiHandlers.get(name);
    if (existing) {
      existing.push(h);
    } else {
      this.multiHandlers.set(name, [h]);
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
    const name = command.constructor.name;

    if (command instanceof KeyedBroadcastCommand) {
      const handlers = this.keyedHandlers.get(name)?.get(command.key) ?? [];
      return Promise.all(
        handlers.map((handler) =>
          (handler as CommandHandler<typeof command, TResult>)(command),
        ),
      );
    }

    const handlers = this.multiHandlers.get(name);
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
