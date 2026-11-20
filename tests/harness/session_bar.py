"""The Session bar's status channel, as the page's script opens it: a
websocket to ``/bases/<id>/session`` carrying the browser's Portal cookie
and the Portal's ``Origin``. While one is open its user is present on the
Remote session. Like the page's script, it renews the Remote session's
lease whenever a status message asks for it (``renew``), unless the test
turns that off (``renewing = False``).

Virtual time doesn't wait for that round trip (the Portal's sweep asks, the
bar answers, both in real time): to let a long while pass with a bar open,
use :meth:`StatusChannel.run`, not ``agent.run``."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed

from sp_rtk_portal.accounts.sessions import COOKIE

from .portal import ORIGIN, Browser

if TYPE_CHECKING:
    from .agent import RunningAgent

STEP = timedelta(minutes=1)
"""How far :meth:`StatusChannel.run` moves virtual time before it lets the
renewals catch up: no more than the renewal interval, so a lease never
nears its end."""


class StatusChannel:
    def __init__(self, ws: ClientConnection, base_id: str) -> None:
        self.ws = ws
        self.base_id = base_id
        self.messages: list[dict[str, Any]] = []
        self.renewing = True
        self.renewals = 0
        """Renewals sent (asked for or not)."""
        self._changed = asyncio.Event()
        self._reader = asyncio.ensure_future(self._read())

    async def _read(self) -> None:
        with contextlib.suppress(ConnectionClosed):
            async for raw in self.ws:
                message = json.loads(raw)
                self.messages.append(message)
                self._changed.set()
                if message.get("renew") and self.renewing:
                    # The Portal may have ended and closed the channel
                    # meanwhile: still read what it sent before closing.
                    with contextlib.suppress(ConnectionClosed):
                        await self._send_renew()
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

    async def _send_renew(self) -> None:
        self.renewals += 1
        await self.ws.send(json.dumps({"type": "renew"}))

    async def renew(self, timeout: float = 5) -> dict[str, Any]:
        """Renew the lease now; returns the status the Portal answers with."""
        seen = len(self.messages)
        await self._send_renew()

        async def wait() -> dict[str, Any]:
            while len(self.messages) == seen:
                self._changed.clear()
                await self._changed.wait()
            return self.messages[-1]

        return await asyncio.wait_for(wait(), timeout)

    async def run(self, agent: RunningAgent, **delta: float) -> None:
        """Let virtual time pass (``bar.run(agent, minutes=60)``) a step at
        a time, waiting (real time) after each until no Remote session with
        a bar open on the base still has a renewal due: the Portal asked
        and the bar's renewal landed, as they would in real time."""
        clock = agent.portal.clock
        tunnels = agent.portal.context.tunnels
        target = clock.now() + timedelta(**delta)
        while (left := target - clock.now()) > timedelta(0):
            await agent.run(seconds=min(left, STEP).total_seconds())
            if not self.renewing:
                continue
            loop = asyncio.get_running_loop()
            give_up = loop.time() + 10
            while any(tunnels.renewal_due(s) for s in tunnels.present(self.base_id)):
                if loop.time() > give_up:
                    raise AssertionError("the bar never renewed the lease")
                await asyncio.sleep(0.001)

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
    channel = StatusChannel(ws, base_id)
    try:
        yield channel
    finally:
        await channel.close()
