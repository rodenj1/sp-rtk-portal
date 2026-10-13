"""The Session bar's status channel, as the page's script opens it: a
websocket to ``/bases/<id>/session`` carrying the browser's Portal cookie
and the Portal's ``Origin``. While one is open its user is present on the
Remote session."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed

from sp_rtk_portal.accounts.sessions import COOKIE

from .portal import ORIGIN, Browser


class StatusChannel:
    def __init__(self, ws: ClientConnection) -> None:
        self.ws = ws
        self.messages: list[dict[str, Any]] = []
        self._changed = asyncio.Event()
        self._reader = asyncio.ensure_future(self._read())

    async def _read(self) -> None:
        with contextlib.suppress(ConnectionClosed):
            async for raw in self.ws:
                self.messages.append(json.loads(raw))
                self._changed.set()
        self._changed.set()

    @property
    def state(self) -> str | None:
        return self.messages[-1]["state"] if self.messages else None

    async def until(self, state: str, timeout: float = 5) -> dict[str, Any]:
        async def wait() -> dict[str, Any]:
            while self.state != state:
                self._changed.clear()
                await self._changed.wait()
            return self.messages[-1]

        return await asyncio.wait_for(wait(), timeout)

    async def close(self) -> None:
        await self.ws.close()
        await self._reader


@asynccontextmanager
async def status_channel(
    port: int, browser: Browser, base_id: str, origin: str = ORIGIN
) -> AsyncIterator[StatusChannel]:
    cookie = browser.cookies.get(COOKIE)
    ws = await connect(
        f"ws://127.0.0.1:{port}/bases/{base_id}/session",
        additional_headers={"Cookie": f"{COOKIE}={cookie}", "Origin": origin},
    )
    channel = StatusChannel(ws)
    try:
        yield channel
    finally:
        await channel.close()
