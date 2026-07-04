import { describe, it, expect, vi } from "vitest";
import { InMemoryEventBus } from "./event-bus.ts";

describe("InMemoryEventBus", () => {
  it("delivers event to subscriber", () => {
    const bus = new InMemoryEventBus();
    const handler = vi.fn();

    bus.subscribe("test:event", handler);
    bus.publish("test:event", "hello");

    expect(handler).toHaveBeenCalledWith("hello");
  });

  it("delivers event to multiple subscribers", () => {
    const bus = new InMemoryEventBus();
    const handler1 = vi.fn();
    const handler2 = vi.fn();

    bus.subscribe("test:event", handler1);
    bus.subscribe("test:event", handler2);
    bus.publish("test:event", "hello");

    expect(handler1).toHaveBeenCalledWith("hello");
    expect(handler2).toHaveBeenCalledWith("hello");
  });

  it("does not deliver events to subscribers of different event types", () => {
    const bus = new InMemoryEventBus();
    const handlerA = vi.fn();

    bus.subscribe("test:event-a", handlerA);
    bus.publish("test:event-b", "hello");

    expect(handlerA).not.toHaveBeenCalled();
  });

  it("supports async subscribers", async () => {
    const bus = new InMemoryEventBus();
    let called = false;

    bus.subscribe("test:event", async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
      called = true;
    });
    bus.publish("test:event", "hello");

    // The publish is fire-and-forget, but the handler still runs.
    // Wait for the async handler to complete.
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(called).toBe(true);
  });
});
