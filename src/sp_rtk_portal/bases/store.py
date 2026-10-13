"""Reading bases for the Portal's pages."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from sp_rtk_portal.db import Connection

Role = Literal["operator", "shared"]
OPERATOR: Role = "operator"
SHARED: Role = "shared"


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
    remote_paused: bool = False
    """Remote access paused on site: Open remotely is refused."""
    role: Role = "operator"
    """How the reader reaches it: their own Claim, or a Share."""


_COLUMNS = (
    "id, name, software_version, last_seen_at, protocol_version, metered,"
    " polled_metered, lan_addresses, host(public_ip) AS public_ip, doorbell,"
    " needs_upgrade, remote_paused"
)
_ROLE = (
    "CASE WHEN base.owner_account_id = %(account)s THEN 'operator'"
    " ELSE 'shared' END AS role"
)
_REACHABLE = (
    "(base.owner_account_id = %(account)s OR EXISTS (SELECT 1 FROM share"
    " WHERE share.base_id = base.id AND share.account_id = %(account)s))"
)


async def owned_by(conn: Connection, account_id: int) -> list[BaseSummary]:
    """The bases ``account_id`` Claimed, by name."""
    cur = await conn.execute(
        f"SELECT {_COLUMNS} FROM base"
        " WHERE owner_account_id = %s ORDER BY lower(name), id",
        (account_id,),
    )
    return [BaseSummary(**row) for row in await cur.fetchall()]


async def listed_for(conn: Connection, account_id: int) -> list[BaseSummary]:
    """The bases ``account_id`` Claimed or was Shared, by name."""
    cur = await conn.execute(
        f"SELECT {_COLUMNS}, {_ROLE} FROM base WHERE {_REACHABLE}"
        " ORDER BY lower(name), id",
        {"account": account_id},
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
    """``base_id`` if ``account_id`` may open it remotely (its Operator or a
    Shared user; ``.role`` says which), else ``None``."""
    cur = await conn.execute(
        f"SELECT {_COLUMNS}, {_ROLE} FROM base WHERE id = %(base)s AND {_REACHABLE}",
        {"account": account_id, "base": base_id},
    )
    row = await cur.fetchone()
    return BaseSummary(**row) if row else None
