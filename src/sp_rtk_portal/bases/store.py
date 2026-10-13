"""Reading bases for the Portal's pages."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sp_rtk_portal.db import Connection


@dataclass(frozen=True)
class BaseSummary:
    id: str
    name: str
    software_version: str
    last_seen_at: datetime | None
    protocol_version: int = 0
    metered: bool = False
    polled_metered: bool = False
    lan_addresses: list[dict[str, Any]] = field(default_factory=list)
    """``{address, interface, primary}`` from the latest Check-in."""
    public_ip: str | None = None
    doorbell: str = "off"
    needs_upgrade: bool = False


_COLUMNS = (
    "id, name, software_version, last_seen_at, protocol_version, metered,"
    " polled_metered, lan_addresses, host(public_ip) AS public_ip, doorbell,"
    " needs_upgrade"
)


async def owned_by(conn: Connection, account_id: int) -> list[BaseSummary]:
    """The bases ``account_id`` Claimed, by name."""
    cur = await conn.execute(
        f"SELECT {_COLUMNS} FROM base"
        " WHERE owner_account_id = %s ORDER BY lower(name), id",
        (account_id,),
    )
    return [BaseSummary(**row) for row in await cur.fetchall()]


async def set_metered(
    conn: Connection, base_id: str, account_id: int, metered: bool
) -> bool:
    """Mark the Operator's base metered (or not). ``False``: not theirs."""
    cur = await conn.execute(
        "UPDATE base SET metered = %s WHERE id = %s AND owner_account_id = %s",
        (metered, base_id, account_id),
    )
    return cur.rowcount > 0


async def reachable_by(
    conn: Connection, account_id: int, base_id: str
) -> BaseSummary | None:
    """``base_id`` if ``account_id`` may open it remotely (its owner; Shares
    add Shared users, #91), else ``None``."""
    cur = await conn.execute(
        f"SELECT {_COLUMNS} FROM base WHERE id = %s AND owner_account_id = %s",
        (base_id, account_id),
    )
    row = await cur.fetchone()
    return BaseSummary(**row) if row else None
