import asyncio
from typing import List, Callable

class EventBus:
    def __init__(self):
        self.subscribers: List[Callable] = []

    def subscribe(self, callback: Callable):
        self.subscribers.append(callback)

    async def emit(self, event_name: str, payload: dict):
        message = {"event": event_name, "payload": payload}
        for subscriber in self.subscribers:
            if asyncio.iscoroutinefunction(subscriber):
                await subscriber(message)
            else:
                subscriber(message)

bus = EventBus()
