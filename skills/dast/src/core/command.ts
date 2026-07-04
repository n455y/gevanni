export abstract class Command<TResult> {
  abstract readonly type: string;
  declare readonly _result: TResult;
}

export abstract class SingleCommand<TResult> extends Command<TResult> {}

export abstract class PartitionedSingleCommand<TResult> extends SingleCommand<TResult> {
  abstract readonly partition: string;
}

export abstract class BroadcastCommand<TResult> extends Command<TResult> {}

export abstract class PartitionedBroadcastCommand<TResult> extends BroadcastCommand<TResult> {
  abstract readonly partition: string;
}

export abstract class PipelineCommand<TAccumulator> extends Command<TAccumulator> {
  abstract readonly initial: TAccumulator;
}

export abstract class PartitionedPipelineCommand<TAccumulator> extends PipelineCommand<TAccumulator> {
  abstract readonly partition: string;
}

export type CommandHandler<TCommand, TResult> = (
  command: TCommand,
) => Promise<TResult>;

export type PipelineHandler<TCommand, TAccumulator> = (
  command: TCommand,
  accumulator: TAccumulator,
) => Promise<TAccumulator>;
