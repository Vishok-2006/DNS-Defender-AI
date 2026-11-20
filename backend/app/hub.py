"""WebSocket fan-out (thread-safe publish from sync code and background tasks)."""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional, Set

from fastapi import WebSocket

log = logging.getLogger("defender.hub")


class EventHub:
    def __init__(self) -> None:
        self._clients: Dict[str, Set[WebSocket]] = {"alerts": set(), "traffic": set()}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, channel: str, ws: WebSocket) -> None:
        await ws.accept()
        self._clients[channel].add(ws)

    def disconnect(self, channel: str, ws: WebSocket) -> None:
        self._clients[channel].discard(ws)

    def count(self, channel: str) -> int:
        return len(self._clients[channel])

    def publish(self, channel: str, message: dict) -> None:
        """Safe to call from any thread."""
        if self._loop is None or not self._clients[channel]:
            return
        asyncio.run_coroutine_threadsafe(self._broadcast(channel, message), self._loop)

    async def _broadcast(self, channel: str, message: dict) -> None:
        for ws in list(self._clients[channel]):
            try:
                await ws.send_json(message)
            except Exception:  # dead socket
                self._clients[channel].discard(ws)
