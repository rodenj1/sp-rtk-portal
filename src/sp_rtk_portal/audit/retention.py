"""Audit entries are kept 90 days (``log.RETENTION``), then deleted.

``purge`` deletes what is older; ``Purger`` runs it at startup and then
every ``Settings.audit_purge_interval`` seconds (real time; the age is
measured on the Portal's clock).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import datetime

from sp_rtk_portal.audit.log import RETENTION
from sp_rtk_portal.clock import Clock
from sp_rtk_portal.db import Connection, Database

log = logging.getLogger(__name__)


async def purge(conn: Connection, now: datetime) -> int:
    """Delete entries older than the retention period; how many went."""
    cur = await conn.execute(
        "DELETE FROM audit_entry WHERE at < %s", (now - RETENTION,)
    )
    return cur.rowcount


class Purger:
    def __init__(self, db: Database, clock: Clock, interval: float) -> None:
        self._db = db
        self._clock = clock
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
                    gone = await purge(conn, self._clock.now())
                if gone:
                    log.info("Purged %d audit entries older than %s", gone, RETENTION)
            except Exception:
                log.exception("Audit purge failed")
            await asyncio.sleep(self._interval)
