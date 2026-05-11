export interface EventBus {
  publish<T>(event: string, data: T): void;
  subscribe<T>(event: string, handler: (data: T) => void | Promise<void>): void;
}

export class InMemoryEventBus implements EventBus {
  private subscribers = new Map<string, Array<(data: any) => void | Promise<void>>>();

  subscribe<T>(event: string, handler: (data: T) => void | Promise<void>): void {
    const existing = this.subscribers.get(event);
    if (existing) {
      existing.push(handler);
    } else {
      this.subscribers.set(event, [handler]);
    }
  }

  publish<T>(event: string, data: T): void {
    const handlers = this.subscribers.get(event);
    if (!handlers) {
      return;
    }
    for (const handler of handlers) {
      handler(data);
    }
  }
}
