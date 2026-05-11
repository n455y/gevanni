export abstract class Command<TResult> {
  abstract readonly type: string;
  declare readonly _result: TResult;
}

export abstract class SingleCommand<TResult> extends Command<TResult> {}

export abstract class BroadcastCommand<TResult> extends Command<TResult> {}

export abstract class PipelineCommand<TAccumulator> extends Command<TAccumulator> {
  abstract readonly initial: TAccumulator;
}

export type CommandHandler<TCommand, TResult> = (
  command: TCommand,
) => Promise<TResult>;

export type PipelineHandler<TCommand, TAccumulator> = (
  command: TCommand,
  accumulator: TAccumulator,
) => Promise<TAccumulator>;
