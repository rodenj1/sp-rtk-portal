"""The agent's HTTPS to the Portal over a real wire: TCP and TLS on
127.0.0.1, through a :class:`Wire` that counts connections and bytes.

:class:`CloudflareTransport` hands each request straight to the app, so it
has no connections to keep or lose. Tests about the connection itself
(ticket #201: polls reuse it) opt into this one instead::

    async with wire(portal) as w, running_agent(portal, transport=w.transport) as a:
        ...

The agent's requests still get ``CF-Connecting-IP`` and land in
``agent.requests`` and ``agent.traffic``; on the way they go through the
agent's own pool (``ipv4_transport``: its limits and idle expiry), over TLS
to the Portal served by uvicorn. Only the pool's network changes: it
connects to the wire whatever host it asks for. While the wire is up,
httpcore's idle timer runs on virtual time too, as it would between real
polls. ``w.connections`` counts the TCP connections the agent opened,
``w.sent``/``w.received`` the bytes on them (TLS records, handshakes
included), and ``w.close()`` plays the Portal or the network closing them.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
import types
from collections.abc import AsyncIterator, Iterable, Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import TYPE_CHECKING

import httpcore
import httpx
from sp_rtk_base.portal_agent.portal_api import ipv4_transport

from .agent import CloudflareTransport
from .clock import FakeClock
from .portal import Portal
from .server import localhost_tls, serving

if TYPE_CHECKING:
    from .agent import RunningAgent


class Wire:
    """A TCP relay between the agent and the Portal: what Cloudflare and the
    internet look like from the base, connection by connection."""

    def __init__(self, upstream: int) -> None:
        self._upstream = upstream
        self.port = 0
        self.connections = 0
        """TCP connections the agent opened."""
        self.sent = self.received = 0
        """Bytes the agent sent and received on them."""
        self._open: set[asyncio.StreamWriter] = set()
        self._pipes: set[asyncio.Task[None]] = set()

    def transport(self, agent: RunningAgent) -> httpx.AsyncBaseTransport:
        return WireTransport(agent, self)

    async def close(self) -> None:
        """The Portal (or a NAT on the way) closes every open connection."""
        for writer in list(self._open):
            writer.close()
        await asyncio.sleep(0.05)  # the agent's side sees the close

    async def _relay(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.connections += 1
        up_reader, up_writer = await asyncio.open_connection(
            "127.0.0.1", self._upstream
        )
        self._open |= {writer, up_writer}
        pipes = [
            asyncio.create_task(self._pipe(reader, up_writer, up=True)),
            asyncio.create_task(self._pipe(up_reader, writer, up=False)),
        ]
        self._pipes.update(pipes)
        await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
        for w in (writer, up_writer):
            w.close()
            self._open.discard(w)
        for p in pipes:
            p.cancel()
            self._pipes.discard(p)

    async def _pipe(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, up: bool
    ) -> None:
        with contextlib.suppress(ConnectionError, OSError):
            while data := await reader.read(65536):
                if up:
                    self.sent += len(data)
                else:
                    self.received += len(data)
                writer.write(data)
                await writer.drain()


class _ToWire(httpcore.AsyncNetworkBackend):
    """Connects wherever the agent asks (the Portal's public host) to the
    wire instead."""

    def __init__(self, port: int) -> None:
        self._port = port
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._inner.connect_tcp("127.0.0.1", self._port, timeout=timeout)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise NotImplementedError

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def _trust_any() -> ssl.SSLContext:
    # The throwaway certificate names localhost, not the Portal's host.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class _NoNames:
    async def address(self, host: str) -> str | None:
        return None

    def forget(self, host: str) -> None:
        pass


class WireTransport(CloudflareTransport):
    """:class:`CloudflareTransport`, but over the agent's own pool and the
    :class:`Wire`."""

    def __init__(self, agent: RunningAgent, wire: Wire) -> None:
        super().__init__(agent.portal.app, agent.ip, agent)
        inner = ipv4_transport(_NoNames(), verify=_trust_any())
        pool = inner._pool  # pyright: ignore[reportPrivateUsage]
        pool._network_backend = _ToWire(wire.port)  # pyright: ignore[reportPrivateUsage]
        self._inner = inner  # type: ignore[assignment]

    async def aclose(self) -> None:
        """The agent lets its connections go (it may connect again)."""
        await self._inner.aclose()


@contextmanager
def _virtual_idle_timer(clock: FakeClock) -> Iterator[None]:
    """httpcore's keep-alive expiry reads ``time.monotonic()``: move it on
    with the fake clock."""
    module = httpcore._async.http11  # pyright: ignore[reportPrivateUsage]
    real, start = module.time, clock.now()
    module.time = types.SimpleNamespace(  # type: ignore[assignment]
        monotonic=lambda: time.monotonic() + (clock.now() - start).total_seconds()
    )
    try:
        yield
    finally:
        module.time = real


@asynccontextmanager
async def wire(portal: Portal) -> AsyncIterator[Wire]:
    """The Portal served over HTTPS behind a :class:`Wire`."""
    with localhost_tls() as tls, _virtual_idle_timer(portal.clock):
        # Keep-alive as long as any test runs: only ``Wire.close`` ends one.
        async with serving(portal.app, tls=tls, timeout_keep_alive=3600) as port:
            w = Wire(port)
            server = await asyncio.start_server(w._relay, "127.0.0.1", 0)  # pyright: ignore[reportPrivateUsage]
            w.port = server.sockets[0].getsockname()[1]
            try:
                yield w
            finally:
                server.close()
                await w.close()
                for p in list(w._pipes):  # pyright: ignore[reportPrivateUsage]
                    p.cancel()
