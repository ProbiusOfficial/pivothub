"""WebSocket 连接管理与广播。"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket

log = logging.getLogger("pivothub.ws")


class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []
        self.loop: asyncio.AbstractEventLoop | None = None

    def note_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """记录主事件循环，允许后台线程（适配器子进程监听等）安全广播。"""
        self.loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)
        await self.broadcast_raw({"type": "ws.online", "online": True, "clients": len(self.active)})

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast_raw(self, payload: dict[str, Any]) -> None:
        text = json.dumps(payload, ensure_ascii=False)
        dead: list[WebSocket] = []
        for ws in list(self.active):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def push(self, type_: str, **payload: Any) -> None:
        """线程安全便捷入口：任意线程/协程均可调用。"""
        msg = {"type": type_, **payload}
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast_raw(msg), self.loop)
        else:  # pragma: no cover
            log.debug("无事件循环，丢弃广播 %s", msg)


manager = ConnectionManager()


async def broadcast(type_: str, **payload: Any) -> None:
    await manager.broadcast_raw({"type": type_, **payload})
