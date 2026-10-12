"""The real Portal agent (sp-rtk-base's ``sp_rtk_base.portal_agent``),
running in-process alongside the Portal under test.

It is the same code the base runs: ``PortalAgent`` behind its control
socket, driven through the client the base's local Portal page uses. Only
its edges are wired to the harness:

- its HTTPS goes through :class:`CloudflareTransport` straight into the
  Portal app, with the ``CF-Connecting-IP`` Cloudflare would add; the agent
  signs the public URL (``https://sp-rtk-base.big-spray.com/...``) as it
  would in production;
- its clock is the Portal's fake clock, and its sleeps move that clock
  forward (with a real tick, so a test can act between polls);
- its state directory is a temp dir, so a "restart" or a "reinstall" is a
  new ``PortalAgent`` over the same directory.

sp-rtk-base is a dev dependency by path (``../sp-rtk-base``, the sibling
submodule in the rtk_development meta repo); see the README.
"""

from __future__ import annotations

import asyncio
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from sp_rtk_base.portal_agent.client import read_status, start_claim
from sp_rtk_base.portal_agent.control import PortalAgent, serve
from sp_rtk_base.portal_agent.protocol import AgentStatus

from .portal import Portal

BASE_IP = "198.51.100.30"
"""The base's public IP, as Cloudflare reports it."""


class CloudflareTransport(httpx.AsyncBaseTransport):
    """What sits between a base and the Portal: adds ``CF-Connecting-IP``."""

    def __init__(self, app: object, ip: str) -> None:
        self._ip = ip
        self._inner = httpx.ASGITransport(app=app, client=(ip, 443))  # type: ignore[arg-type]

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request.headers["CF-Connecting-IP"] = self._ip
        return await self._inner.handle_async_request(request)


class RunningAgent:
    def __init__(self, portal: Portal, state_dir: Path, sock: Path, ip: str) -> None:
        self.portal = portal
        self.state_dir = state_dir
        self.sock = sock
        self.ip = ip
        self._agent: PortalAgent | None = None
        self._server: asyncio.Server | None = None

    async def _sleep(self, seconds: float) -> None:
        self.portal.clock.advance(seconds=seconds)
        await asyncio.sleep(0.002)

    async def start(self) -> None:
        self._agent = PortalAgent(
            self.state_dir,
            portal_url=self.portal.origin,
            transport=CloudflareTransport(self.portal.app, self.ip),
            now=self.portal.clock.now,
            sleep=self._sleep,
            name="pi-north",
        )
        self._server = await serve(self.sock, self._agent)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        if self._agent is not None:
            await self._agent.close()
        self._agent = self._server = None

    async def restart(self) -> None:
        await self.stop()
        await self.start()

    async def connect(self) -> AgentStatus:
        """The local page's "Connect to Portal"."""
        return await start_claim(self.sock)

    async def status(self) -> AgentStatus:
        return await read_status(self.sock)

    async def until(self, state: str, timeout: float = 10) -> AgentStatus:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            status = await self.status()
            if status.state == state:
                return status
            if asyncio.get_running_loop().time() > deadline:
                raise AssertionError(f"agent never reached {state}: {status}")
            await asyncio.sleep(0.01)


@asynccontextmanager
async def running_agent(
    portal: Portal, ip: str = BASE_IP
) -> AsyncIterator[RunningAgent]:
    # AF_UNIX paths are capped near 108 bytes: keep the temp dir short.
    with tempfile.TemporaryDirectory(prefix="agent-") as d:
        agent = RunningAgent(portal, Path(d) / "state", Path(d) / "control.sock", ip)
        await agent.start()
        try:
            yield agent
        finally:
            await agent.stop()
