"""How many bases hold their tunnel, poll or are reconnecting, in the logs
(ticket #209), so the homelab owner notices if the fallback to polling
becomes common.

``count`` counts online bases by connection mode (:mod:`.online`'s rules:
a holding base while its tunnel is connected, a reconnecting one for the
grace period after its last sign of life, a polling one until it misses 3
beats); every other Claimed base is offline. ``ModeCounter`` logs it at
startup and then every ``Settings.mode_count_interval`` seconds (real time;
online state is measured on the Portal's clock).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from datetime import datetime

from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.bases.online import HELD_GRACE, MISSED_BEATS
from sp_rtk_portal.clock import Clock
from sp_rtk_portal.config import Settings
from sp_rtk_portal.db import Connection, Database

log = logging.getLogger(__name__)

_BEAT = (
    "greatest(CASE WHEN metered THEN %(metered)s ELSE %(plain)s END,"
    " CASE WHEN polled_metered THEN %(metered)s ELSE %(plain)s END)"
)


@dataclass(frozen=True)
class Modes:
    holding: int
    polling: int
    reconnecting: int
    offline: int


async def count(conn: Connection, settings: Settings, now: datetime) -> Modes:
    config = await agent_config.current(conn, settings)
    cur = await conn.execute(
        "SELECT"
        " count(*) FILTER (WHERE online AND connection_mode = 'holding')"
        "  AS holding,"
        " count(*) FILTER (WHERE online AND connection_mode = 'polling')"
        "  AS polling,"
        " count(*) FILTER (WHERE online AND connection_mode = 'reconnecting')"
        "  AS reconnecting,"
        " count(*) FILTER (WHERE NOT online) AS offline"
        " FROM (SELECT connection_mode, NOT needs_upgrade"
        "  AND last_seen_at IS NOT NULL AND (connection_mode = 'holding'"
        "   OR (connection_mode = 'reconnecting' AND last_seen_at > %(grace)s)"
        f"   OR (connection_mode = 'polling' AND last_seen_at > %(now)s"
        f"       - make_interval(secs => %(beats)s * {_BEAT})))"
        "  AS online FROM base) AS bases",
        {
            "now": now,
            "grace": now - HELD_GRACE,
            "beats": MISSED_BEATS,
            "metered": config.metered_poll_interval,
            "plain": config.poll_interval,
        },
    )
    row = await cur.fetchone()
    assert row is not None
    return Modes(**row)


class ModeCounter:
    def __init__(
        self, db: Database, clock: Clock, settings: Settings, interval: float
    ) -> None:
        self._db = db
        self._clock = clock
        self._settings = settings
        self._interval = interval
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _run(self) -> None:
        while True:
            try:
                async with self._db.connection() as conn:
                    modes = await count(conn, self._settings, self._clock.now())
                log.info(
                    "Bases by connection mode: %d holding, %d polling,"
                    " %d reconnecting, %d offline",
                    modes.holding,
                    modes.polling,
                    modes.reconnecting,
                    modes.offline,
                )
            except Exception:
                log.exception("Counting bases by connection mode failed")
            await asyncio.sleep(self._interval)
