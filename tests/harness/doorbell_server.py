"""A stub Doorbell server (in production it runs on the NTRIP relay VPS; not
deployed in v1).

It does what the real one must, and nothing more: real UDP on 127.0.0.1,
each keepalive relayed with its source address to the Portal's
``/doorbell/keepalives``, and a long poll on ``/doorbell/rings`` whose rings
it sends down the path the keepalives came up. It talks to the Portal app
over HTTPS-shaped requests (httpx into the ASGI app) with the Doorbell token.

- ``received``: every datagram that reached it; ``results``: what the Portal
  said about each relayed keepalive; ``rung``: each ring sent
  ``(packet, (address, port))``.
- ``deaf = True``: drop keepalives (the Doorbell server is down).
- ``send(packet, to)``: send any datagram from the server's socket (a
  forged ring).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from sp_rtk_portal_protocol import (
    HeardKeepalive,
    KeepalivesReply,
    KeepalivesReport,
    Rings,
    doorbell,
)

DOORBELL_TOKEN = "doorbell-test-token"


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, server: StubDoorbell) -> None:
        self._server = server

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self._server.datagram(data, (str(addr[0]), int(addr[1])))


class StubDoorbell:
    def __init__(self, app: Any, origin: str, token: str = DOORBELL_TOKEN) -> None:
        self.http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=origin,
            headers={"Authorization": f"Bearer {token}"},
        )
        self.received: list[tuple[bytes, tuple[str, int]]] = []
        self.results: list[str] = []
        self.rung: list[tuple[bytes, tuple[str, int]]] = []
        self.deaf = False
        self.arrived = 0
        """Datagrams that reached the socket (deaf or not)."""
        self.port = 0
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._changed = asyncio.Condition()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _Udp(self), local_addr=("127.0.0.1", 0)
        )
        self.port = int(self._transport.get_extra_info("sockname")[1])
        self._spawn(self._ring_loop())

    async def stop(self) -> None:
        for task in list(self._tasks):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, httpx.HTTPError):
                await task
        if self._transport is not None:
            self._transport.close()
        await self.http.aclose()

    def _spawn(self, coro: Any, name: str = "ring-loop") -> None:
        task = asyncio.create_task(coro, name=name)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def datagram(self, data: bytes, source: tuple[str, int]) -> None:
        self.arrived += 1
        if self.deaf:
            return
        self.received.append((data, source))
        self._spawn(self._relay(data, source), name="relay")

    async def _relay(self, data: bytes, source: tuple[str, int]) -> None:
        report = KeepalivesReport(
            keepalives=[
                HeardKeepalive(
                    packet=doorbell.encode_packet(data),
                    address=source[0],
                    port=source[1],
                )
            ]
        )
        resp = await self.http.post(doorbell.KEEPALIVES_PATH, json=report.to_json())
        resp.raise_for_status()
        async with self._changed:
            self.results += KeepalivesReply.from_json(resp.json()).results
            self._changed.notify_all()

    async def _ring_loop(self) -> None:
        while True:
            resp = await self.http.get(doorbell.RINGS_PATH, params={"wait": 5})
            resp.raise_for_status()
            for ring in Rings.from_json(resp.json()).rings:
                packet = doorbell.decode_packet(ring.packet)
                self.send(packet, (ring.address, ring.port))
                self.rung.append((packet, (ring.address, ring.port)))

    def send(self, packet: bytes, to: tuple[str, int]) -> None:
        assert self._transport is not None
        self._transport.sendto(packet, to)

    async def quiet(self, expected: int) -> None:
        """Wait (real time) until ``expected`` datagrams have arrived and
        every relay is answered."""
        loop = asyncio.get_running_loop()
        give_up = loop.time() + 5
        while loop.time() < give_up:
            relays = [t for t in self._tasks if t.get_name().startswith("relay")]
            if self.arrived >= expected and not relays:
                return
            await asyncio.sleep(0.001)
        raise AssertionError(f"{expected} datagrams never arrived ({self.arrived})")

    async def until_relayed(self, count: int, timeout: float = 5) -> list[str]:
        """Wait (real time) until ``count`` keepalives in all were relayed
        and answered; the Portal's verdicts."""
        async with self._changed:
            await asyncio.wait_for(
                self._changed.wait_for(lambda: len(self.results) >= count), timeout
            )
        return list(self.results)


@asynccontextmanager
async def stub_doorbell(app: Any, origin: str) -> AsyncIterator[StubDoorbell]:
    server = StubDoorbell(app, origin)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


BELL_HOST = "bell.example.net"
BELL_ADDRESS = ("93.184.215.14", 4500)
"""The Doorbell server's public address, as the agent's DNS answers it."""


def wire(agent: Any, server: StubDoorbell) -> None:
    """Let ``agent`` (a :class:`~.agent.RunningAgent`) reach ``server`` at
    :data:`BELL_HOST`, and have its virtual time wait for each relay."""
    agent.dns.records[BELL_HOST] = [BELL_ADDRESS[0]]
    agent.udp.routes[BELL_ADDRESS] = ("127.0.0.1", server.port)

    async def quiet() -> None:
        routed = [s for s in agent.udp.sent if s[1] in agent.udp.routes]
        await server.quiet(len(routed))

    agent.time.quiesce.append(quiet)
