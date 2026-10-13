"""The real Portal agent (sp-rtk-base's ``sp_rtk_base.portal_agent``),
running in-process alongside the Portal under test.

It is the same code the base runs: ``PortalAgent`` behind its control
socket, driven through the client the base's local Portal page uses. Only
its edges are wired to the harness:

- its HTTPS goes through :class:`CloudflareTransport` straight into the
  Portal app, with the ``CF-Connecting-IP`` Cloudflare would add; the agent
  signs the public URL (``https://sp-rtk-base.big-spray.com/...``) as it
  would in production;
- its clock is the Portal's fake clock, and its sleeps are virtual
  (:class:`AgentTime`): nothing happens until the test lets time pass with
  ``agent.run(seconds=...)`` or ``agent.until(state)``;
- DNS (for a Doorbell host) is :class:`FakeDns`, and its LAN addresses are
  ``agent.lan``;
- its UDP (the Doorbell) is real, on 127.0.0.1: :class:`NatUdp` sends what
  the agent addresses to a public ``(address, port)`` in ``agent.udp.routes``
  to the local port it maps to (a stub Doorbell server), and shows replies
  as coming from that public address. ``agent.udp.sent`` is everything the
  agent tried to send;
- its state directory is a temp dir, so a "restart" or a "reinstall" is a
  new ``PortalAgent`` over the same directory;
- its tunnel (a real websocket) goes to the Portal served over TCP
  (``server_port``, see :mod:`.server`) whatever URL the agent asks for;
  the URLs it asked for are in ``agent.tunnel_urls``. Its streams go to
  ``app_port`` (the :mod:`.base_ui` stub) instead of ``:8080``.

sp-rtk-base is a dev dependency by path (``../sp-rtk-base``, the sibling
submodule in the rtk_development meta repo); see the README.
"""

from __future__ import annotations

import asyncio
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from sp_rtk_base.portal_agent.client import read_status, start_claim, unclaim
from sp_rtk_base.portal_agent.control import PortalAgent, serve
from sp_rtk_base.portal_agent.protocol import AgentStatus
from sp_rtk_portal_protocol import PROTOCOL_VERSION, BaseKey, LanAddress
from websockets.asyncio.client import connect as ws_connect

from .agent_time import AgentTime
from .portal import CLOUDFLARED, Browser, Portal

BASE_IP = "198.51.100.30"
"""The base's public IP, as Cloudflare reports it."""


class CloudflareTransport(httpx.AsyncBaseTransport):
    """What sits between a base and the Portal: adds ``CF-Connecting-IP``."""

    def __init__(self, app: object, ip: str, agent: RunningAgent) -> None:
        self._ip = ip
        self._agent = agent
        self._inner = httpx.ASGITransport(app=app, client=(CLOUDFLARED, 443))  # type: ignore[arg-type]

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if not self._agent.reachable:
            raise httpx.ConnectError("the base is offline", request=request)
        self._agent.traffic.count_request(request)
        request.headers["CF-Connecting-IP"] = self._agent.ip
        response = await self._inner.handle_async_request(request)
        await response.aread()
        self._agent.traffic.count_response(response)
        self._agent.requests.append(
            Sent(
                self._agent.portal.clock.now(),
                request.url.path,
                response.status_code,
                response.headers.get("retry-after"),
            )
        )
        return response


@dataclass(frozen=True)
class Sent:
    """One request the agent sent the Portal, and how it was answered."""

    at: datetime
    path: str
    status: int
    retry_after: str | None


class Traffic:
    """HTTP/1.1 bytes the agent sent and received (headers and bodies, as on
    the wire inside TLS), for the polling-cost estimate."""

    def __init__(self) -> None:
        self.sent = self.received = self.requests = 0

    @staticmethod
    def _headers(headers: httpx.Headers) -> int:
        return sum(len(k) + len(v) + 4 for k, v in headers.raw) + 2

    def count_request(self, request: httpx.Request) -> None:
        self.requests += 1
        line = f"{request.method} {request.url.raw_path.decode()} HTTP/1.1\r\n"
        self.sent += len(line) + self._headers(request.headers) + len(request.content)

    def count_response(self, response: httpx.Response) -> None:
        line = f"HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n"
        self.received += (
            len(line) + self._headers(response.headers) + len(response.content)
        )


LAN = [
    LanAddress(address="192.168.1.20", interface="eth0", primary=True),
    LanAddress(address="10.8.0.4", interface="wlan0", primary=False),
]


class FakeDns:
    """The agent's resolver: answers from ``records`` (else no such host)."""

    def __init__(self) -> None:
        self.records: dict[str, list[str]] = {}

    async def __call__(self, host: str, port: int) -> list[str]:
        if host not in self.records:
            raise OSError(f"{host}: Name or service not known")
        return list(self.records[host])


class _NatSocket:
    def __init__(self, udp: NatUdp, transport: asyncio.DatagramTransport) -> None:
        self._udp, self._transport = udp, transport

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        self._udp.sent.append((data, addr))
        local = self._udp.routes.get(addr)
        if local is not None:
            self._transport.sendto(data, local)

    def close(self) -> None:
        self._transport.close()


class _NatProtocol(asyncio.DatagramProtocol):
    def __init__(self, udp: NatUdp, on_datagram: Any) -> None:
        self._udp, self._on_datagram = udp, on_datagram

    def datagram_received(self, data: bytes, addr: Any) -> None:
        source = (str(addr[0]), int(addr[1]))
        public = {local: public for public, local in self._udp.routes.items()}
        self._on_datagram(data, public.get(source, source))


class NatUdp:
    """The agent's ``open_udp``: real UDP on 127.0.0.1 with public addresses
    translated (the base's router and the internet, in one)."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, int], tuple[str, int]] = {}
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    async def __call__(self, address: str, on_datagram: Any) -> _NatSocket:
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: _NatProtocol(self, on_datagram), local_addr=("127.0.0.1", 0)
        )
        return _NatSocket(self, transport)


class RunningAgent:
    def __init__(
        self,
        portal: Portal,
        state_dir: Path,
        sock: Path,
        ip: str,
        *,
        server_port: int | None = None,
        app_port: int | None = None,
    ) -> None:
        self.portal = portal
        self.server_port = server_port
        self.app_port = app_port
        self.tunnel_urls: list[str] = []
        """Every tunnel URL the agent tried to open."""
        self.state_dir = state_dir
        self.sock = sock
        self.ip = ip
        self.time = AgentTime(portal.clock)
        self.dns = FakeDns()
        self.udp = NatUdp()
        self.lan: list[LanAddress] = list(LAN)
        self.protocol_version = PROTOCOL_VERSION
        """What the agent sends; raise it to "upgrade" sp-rtk-base."""
        self.traffic = Traffic()
        self.requests: list[Sent] = []
        """Every request the agent sent, in order."""
        self.reachable = True
        """``False``: the base is cut off (its requests fail to connect)."""
        self._agent: PortalAgent | None = None
        self._server: asyncio.Server | None = None

    @property
    def key(self) -> BaseKey:
        """The base key the agent made at Claim (to play it by hand)."""
        return BaseKey.from_pem((self.state_dir / "base_key.pem").read_bytes())

    async def _tunnel_connect(self, url: str, headers: dict[str, str]) -> Any:
        self.tunnel_urls.append(url)
        if self.server_port is None or not self.reachable:
            raise OSError("no Portal served for the tunnel")
        return await ws_connect(
            f"ws://127.0.0.1:{self.server_port}{urlsplit(url).path}",
            additional_headers={**headers, "CF-Connecting-IP": self.ip},
        )

    async def start(self) -> None:
        extra: dict[str, Any] = {
            "tunnel_connect": self._tunnel_connect,
            "open_udp": self.udp,
        }
        if self.app_port is not None:
            extra["app_port"] = self.app_port
        self._agent = PortalAgent(
            self.state_dir,
            portal_url=self.portal.origin,
            transport=CloudflareTransport(self.portal.app, self.ip, self),
            now=self.portal.clock.now,
            sleep=self.time.sleep,
            name="pi-north",
            resolve=self.dns,
            lan_addresses=lambda: list(self.lan),
            protocol_version=self.protocol_version,
            **extra,
        )
        self._server = await serve(self.sock, self._agent)
        if self._agent.status().state == "connected":
            await self.time.until_asleep()  # its first Check-in and poll

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

    async def claim(self, operator: Browser, name: str = "North field") -> AgentStatus:
        """Connect to Portal, and ``operator`` approves the code: the base is
        Claimed, has Checked in and polled once."""
        pairing = await self.connect()
        assert pairing.user_code, pairing
        resp = await operator.action(
            "/claim", {"code": pairing.user_code, "name": name}
        )
        assert resp.json() == {"next": "/"}, resp.text
        return await self.until("connected")

    async def status(self) -> AgentStatus:
        return await read_status(self.sock)

    async def unclaim(self) -> AgentStatus:
        """The local page's Un-claim."""
        return await unclaim(self.sock)

    async def run(self, **delta: float) -> None:
        """Let virtual time pass (``agent.run(seconds=60)``); the agent polls
        and Checks in on the way, exactly when it would."""
        await self.time.run(**delta)

    async def until(self, state: str, timeout: float = 10) -> AgentStatus:
        """Let virtual time run, sleep by sleep, until the agent is in
        ``state``. Once ``connected``, its first poll has been answered."""
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            status = await self.status()
            if status.state == state:
                if state == "connected":
                    await self.time.until_asleep()
                    status = await self.status()
                return status
            if asyncio.get_running_loop().time() > deadline:
                raise AssertionError(f"agent never reached {state}: {status}")
            if not await self.time.step():
                await asyncio.sleep(0.01)


@asynccontextmanager
async def running_agent(
    portal: Portal,
    ip: str = BASE_IP,
    *,
    server_port: int | None = None,
    app_port: int | None = None,
) -> AsyncIterator[RunningAgent]:
    # AF_UNIX paths are capped near 108 bytes: keep the temp dir short.
    with tempfile.TemporaryDirectory(prefix="agent-") as d:
        agent = RunningAgent(
            portal,
            Path(d) / "state",
            Path(d) / "control.sock",
            ip,
            server_port=server_port,
            app_port=app_port,
        )
        await agent.start()
        try:
            yield agent
        finally:
            await agent.stop()
