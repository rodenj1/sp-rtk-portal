"""Reading bases for the Portal's pages."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sp_rtk_portal.db import Connection


@dataclass(frozen=True)
class BaseSummary:
    id: str
    name: str
    software_version: str
    last_seen_at: datetime | None


async def owned_by(conn: Connection, account_id: int) -> list[BaseSummary]:
    """The bases ``account_id`` Claimed, by name."""
    cur = await conn.execute(
        "SELECT id, name, software_version, last_seen_at FROM base"
        " WHERE owner_account_id = %s ORDER BY lower(name), id",
        (account_id,),
    )
    return [BaseSummary(**row) for row in await cur.fetchall()]
