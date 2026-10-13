"""Return paths and rings (process-local: one Portal instance).

Each keepalive the Doorbell server relays, once verified, records the path
back to its base: the address and port it came from (the base's router).
Every Wake (:meth:`~sp_rtk_portal.tunnel.broker.TunnelBroker.on_wake`) asks
for a ring; the Doorbell server collects due rings with a long poll
(:meth:`Doorbell.rings`) and sends each down its path. A ring carries the
Wake's pending nonce, authenticated with the base's ring key; the base then
opens its tunnel echoing the nonce as for a polled Wake.

A Wake is rung while its nonce is pending, the base's path is fresh (a
keepalive within the Doorbell offline threshold) and its ring key is known:
at once, then again every :data:`RING_RETRY_S` (UDP may drop it), at most
:data:`MAX_RINGS` times. A base without a fresh path still gets the Wake in
its next poll.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from datetime import datetime

from sp_rtk_portal_protocol import Ring, doorbell
from sp_rtk_portal_protocol.doorbell import Keepalive

from sp_rtk_portal.bases.online import DOORBELL_OFFLINE_AFTER
from sp_rtk_portal.bases.presence import DoorbellBase
from sp_rtk_portal.clock import Clock
from sp_rtk_portal.tunnel.broker import TunnelBroker

RING_RETRY_S = 2.0
"""Real seconds between rings of the same Wake."""
MAX_RINGS = 5
MAX_WAIT_S = 30.0
"""The longest a ring long poll is held."""


@dataclass
class _Path:
    address: str
    port: int
    heard_at: datetime
    sent_at: datetime
    """The latest keepalive's own time: an older one is a replay."""
    ring_key: str | None


@dataclass
class _Wanted:
    rings: int = 0
    next_at: float = 0.0
    """Loop time of the next ring."""


class Doorbell:
    def __init__(self, clock: Clock, tunnels: TunnelBroker) -> None:
        self._clock = clock
        self._tunnels = tunnels
        self._paths: dict[str, _Path] = {}
        self._wanted: dict[str, _Wanted] = {}
        self._changed = asyncio.Event()
        tunnels.on_wake(self.want)

    def heard(
        self, base: DoorbellBase, keepalive: Keepalive, address: str, port: int
    ) -> bool:
        """A verified keepalive came from ``address``:``port``. ``False``: not
        newer than the last one from this base (a replay), ignored."""
        path = self._paths.get(base.id)
        if path is not None and keepalive.at <= path.sent_at:
            return False
        self._paths[base.id] = _Path(
            address, port, self._clock.now(), keepalive.at, base.ring_key
        )
        if base.id in self._wanted:
            self._changed.set()
        return True

    def want(self, base_id: str) -> None:
        """A Wake for ``base_id``: ring it."""
        self._wanted.setdefault(base_id, _Wanted())
        self._changed.set()

    def _due(self) -> list[Ring]:
        now, at = self._clock.now(), asyncio.get_running_loop().time()
        due = []
        for base_id, wanted in list(self._wanted.items()):
            nonce = self._tunnels.wake_for_poll(base_id)
            if nonce is None or wanted.rings >= MAX_RINGS:
                del self._wanted[base_id]  # redeemed, expired, or given up
                continue
            path = self._paths.get(base_id)
            if (
                path is None
                or path.ring_key is None
                or now - path.heard_at > DOORBELL_OFFLINE_AFTER
                or at < wanted.next_at
            ):
                continue
            wanted.rings += 1
            wanted.next_at = at + RING_RETRY_S
            packet = doorbell.ring(path.ring_key, nonce, now=now)
            due.append(
                Ring(
                    address=path.address,
                    port=path.port,
                    packet=doorbell.encode_packet(packet),
                )
            )
        return due

    async def rings(self, wait: float) -> list[Ring]:
        """Rings due now, or as soon as some are within ``wait`` seconds."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.0, min(wait, MAX_WAIT_S))
        while True:
            self._changed.clear()
            due = self._due()
            if due or loop.time() >= deadline:
                return due
            wake_at = min(
                [w.next_at for w in self._wanted.values() if w.next_at > loop.time()]
                + [deadline]
            )
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._changed.wait(), wake_at - loop.time())
