"""Signs of life from a Claimed base's agent: polls, Check-ins, and 426s.

Each finds the base by its key's thumbprint (``None``: no such base, the
agent gets 401 ``unclaimed``) and records when it was seen, from which public
IP (``CF-Connecting-IP``) and with which protocol version.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from sp_rtk_portal_protocol import CheckIn

from sp_rtk_portal.db import Connection


@dataclass(frozen=True)
class Seen:
    base_id: str
    metered: bool
    owner_account_id: int | None = None
    paused: bool = False
    was_paused: bool = False
    """Before this poll (a change is audited)."""


async def polled(
    conn: Connection,
    *,
    thumbprint: str,
    now: datetime,
    protocol_version: int,
    ip: str | None,
    paused: bool = False,
) -> Seen | None:
    """A poll; ``paused``: the base reports remote access paused on site."""
    cur = await conn.execute(
        "UPDATE base SET last_seen_at = %s, protocol_version = %s,"
        " public_ip = coalesce(%s::inet, public_ip), needs_upgrade = false,"
        " polled_metered = metered, remote_paused = %s"
        " FROM (SELECT id AS old_id, remote_paused AS was_paused FROM base"
        "       WHERE key_thumbprint = %s FOR UPDATE) AS old"
        " WHERE base.id = old.old_id"
        " RETURNING id, metered, owner_account_id, remote_paused, was_paused",
        (now, protocol_version, ip, paused, thumbprint),
    )
    row = await cur.fetchone()
    if row is None:
        return None
    return Seen(
        row["id"],
        row["metered"],
        owner_account_id=row["owner_account_id"],
        paused=row["remote_paused"],
        was_paused=row["was_paused"],
    )


async def checked_in(
    conn: Connection,
    *,
    thumbprint: str,
    now: datetime,
    protocol_version: int,
    ip: str | None,
    check_in: CheckIn,
) -> Seen | None:
    cur = await conn.execute(
        "UPDATE base SET last_seen_at = %s, last_check_in_at = %s,"
        " protocol_version = %s, public_ip = coalesce(%s::inet, public_ip),"
        " needs_upgrade = false, polled_metered = metered,"
        " software_version = %s, doorbell = %s, lan_addresses = %s"
        " WHERE key_thumbprint = %s RETURNING id, metered",
        (
            now,
            now,
            protocol_version,
            ip,
            check_in.software_version,
            check_in.doorbell,
            json.dumps([a.to_json() for a in check_in.lan_addresses]),
            thumbprint,
        ),
    )
    row = await cur.fetchone()
    return Seen(row["id"], row["metered"]) if row else None


async def refused_as_too_old(
    conn: Connection,
    *,
    thumbprint: str,
    now: datetime,
    protocol_version: int,
    ip: str | None,
) -> None:
    """A 426: the base shows "needs upgrade" (not offline) until it polls
    with a supported version."""
    await conn.execute(
        "UPDATE base SET needs_upgrade = true, last_seen_at = %s,"
        " protocol_version = %s, public_ip = coalesce(%s::inet, public_ip)"
        " WHERE key_thumbprint = %s",
        (now, protocol_version, ip, thumbprint),
    )
