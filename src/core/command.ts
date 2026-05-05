abstract class Command<TResult> {
  abstract readonly type: string;
}

abstract class SingleCommand<TResult> extends Command<TResult> {}

abstract class BroadcastCommand<TResult> extends Command<TResult> {}

abstract class PipelineCommand<TAccumulator> extends Command<TAccumulator> {
  abstract readonly initial: TAccumulator;
}

type CommandHandler<TCommand, TResult> = (
  command: TCommand,
) => Promise<TResult>;

type PipelineHandler<TCommand, TAccumulator> = (
  command: TCommand,
  accumulator: TAccumulator,
) => Promise<TAccumulator>;

export {
  Command,
  SingleCommand,
  BroadcastCommand,
  PipelineCommand,
  type CommandHandler,
  type PipelineHandler,
};
