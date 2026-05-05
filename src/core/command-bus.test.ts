import { describe, it, expect } from "vitest";
import {
  SingleCommand,
  BroadcastCommand,
  PipelineCommand,
} from "./command.js";
import { InMemoryCommandBus } from "./command-bus.js";

class EchoCommand extends SingleCommand<string> {
  readonly type = "echo";
  constructor(readonly message: string) {
    super();
  }
}

class AddCommand extends SingleCommand<number> {
  readonly type = "add";
  constructor(readonly a: number, readonly b: number) {
    super();
  }
}

class CollectCommand extends BroadcastCommand<string[]> {
  readonly type = "collect";
  constructor(readonly input: string) {
    super();
  }
}

class AccumulateCommand extends PipelineCommand<number> {
  readonly type = "accumulate";
  readonly initial = 0;
  constructor(readonly addend: number) {
    super();
  }
}

describe("InMemoryCommandBus", () => {
  describe("dispatch (SingleCommand)", () => {
    it("executes a single handler and returns its result", async () => {
      const bus = new InMemoryCommandBus();
      bus.register(EchoCommand, async (cmd: EchoCommand) => cmd.message);
      const result = await bus.dispatch(new EchoCommand("hello"));
      expect(result).toBe("hello");
    });

    it("throws if no handler is registered for the command", async () => {
      const bus = new InMemoryCommandBus();
      await expect(bus.dispatch(new EchoCommand("hello"))).rejects.toThrow(
        "No handler registered for command: EchoCommand",
      );
    });

    it("overwrites handler when registering again for same command type", async () => {
      const bus = new InMemoryCommandBus();
      bus.register(EchoCommand, async () => "first");
      bus.register(EchoCommand, async () => "second");
      const result = await bus.dispatch(new EchoCommand("hello"));
      expect(result).toBe("second");
    });

    it("passes command instance to handler", async () => {
      const bus = new InMemoryCommandBus();
      bus.register(AddCommand, async (cmd: AddCommand) => cmd.a + cmd.b);
      const result = await bus.dispatch(new AddCommand(3, 7));
      expect(result).toBe(10);
    });
  });

  describe("broadcast (BroadcastCommand)", () => {
    it("executes all registered handlers and returns results array", async () => {
      const bus = new InMemoryCommandBus();
      bus.register(CollectCommand, async (cmd: CollectCommand) => [cmd.input + "-a"]);
      bus.register(CollectCommand, async (cmd: CollectCommand) => [cmd.input + "-b"]);
      const results = await bus.broadcast(new CollectCommand("test"));
      expect(results).toEqual([["test-a"], ["test-b"]]);
    });

    it("returns empty array if no handlers registered", async () => {
      const bus = new InMemoryCommandBus();
      const results = await bus.broadcast(new CollectCommand("test"));
      expect(results).toEqual([]);
    });

    it("appends handlers when registering multiple times", async () => {
      const bus = new InMemoryCommandBus();
      const order: string[] = [];
      bus.register(CollectCommand, async () => {
        order.push("first");
        return ["a"];
      });
      bus.register(CollectCommand, async () => {
        order.push("second");
        return ["b"];
      });
      const results = await bus.broadcast(new CollectCommand("x"));
      expect(results).toEqual([["a"], ["b"]]);
    });
  });

  describe("pipe (PipelineCommand)", () => {
    it("passes accumulator through handlers in sequence", async () => {
      const bus = new InMemoryCommandBus();
      bus.register(AccumulateCommand, async (cmd, acc) => acc + cmd.addend);
      bus.register(AccumulateCommand, async (_cmd, acc) => acc * 2);
      const result = await bus.pipe(new AccumulateCommand(5));
      // initial=0 → +5 = 5 → *2 = 10
      expect(result).toBe(10);
    });

    it("returns initial value if no handlers registered", async () => {
      const bus = new InMemoryCommandBus();
      const result = await bus.pipe(new AccumulateCommand(5));
      expect(result).toBe(0);
    });

    it("executes handlers in registration order", async () => {
      const bus = new InMemoryCommandBus();
      const order: number[] = [];
      bus.register(AccumulateCommand, async (_cmd, acc) => {
        order.push(1);
        return acc + 10;
      });
      bus.register(AccumulateCommand, async (_cmd, acc) => {
        order.push(2);
        return acc + 20;
      });
      bus.register(AccumulateCommand, async (_cmd, acc) => {
        order.push(3);
        return acc + 30;
      });
      const result = await bus.pipe(new AccumulateCommand(0));
      expect(order).toEqual([1, 2, 3]);
      expect(result).toBe(60);
    });
  });
});
