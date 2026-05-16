export abstract class Command<TResult> {
  abstract readonly type: string;
  declare readonly _result: TResult;
}

export interface Keyed {
  readonly key: string;
}

export abstract class SingleCommand<TResult> extends Command<TResult> {}

export abstract class KeyedSingleCommand<TResult> extends SingleCommand<TResult> implements Keyed {
  abstract readonly key: string;
}

export abstract class BroadcastCommand<TResult> extends Command<TResult> {}

export abstract class KeyedBroadcastCommand<TResult> extends BroadcastCommand<TResult> implements Keyed {
  abstract readonly key: string;
}

export abstract class PipelineCommand<TAccumulator> extends Command<TAccumulator> {
  abstract readonly initial: TAccumulator;
}

export abstract class KeyedPipelineCommand<TAccumulator> extends PipelineCommand<TAccumulator> implements Keyed {
  abstract readonly key: string;
}

export type CommandHandler<TCommand, TResult> = (
  command: TCommand,
) => Promise<TResult>;

export type PipelineHandler<TCommand, TAccumulator> = (
  command: TCommand,
  accumulator: TAccumulator,
) => Promise<TAccumulator>;
