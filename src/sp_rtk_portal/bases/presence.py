"""Signs of life from a Claimed base's agent: polls, Check-ins, Doorbell
keepalives (relayed by the Doorbell server), and 426s.

Each finds the base by its key's thumbprint (``None``: no such base, the
agent gets 401 ``unclaimed``) and records when it was seen, from which public
IP (``CF-Connecting-IP``) and with which protocol version.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sp_rtk_portal_protocol import CheckIn, doorbell

from sp_rtk_portal.db import Connection


@dataclass(frozen=True)
class Seen:
    base_id: str
    metered: bool
    last_doorbell_at: datetime | None = None


async def polled(
    conn: Connection,
    *,
    thumbprint: str,
    now: datetime,
    protocol_version: int,
    ip: str | None,
) -> Seen | None:
    cur = await conn.execute(
        "UPDATE base SET last_seen_at = %s, protocol_version = %s,"
        " public_ip = coalesce(%s::inet, public_ip), needs_upgrade = false,"
        " polled_metered = metered"
        " WHERE key_thumbprint = %s RETURNING id, metered",
        (now, protocol_version, ip, thumbprint),
    )
    row = await cur.fetchone()
    return Seen(row["id"], row["metered"]) if row else None


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
        " WHERE key_thumbprint = %s RETURNING id, metered, last_doorbell_at",
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
    return Seen(row["id"], row["metered"], row["last_doorbell_at"]) if row else None


@dataclass(frozen=True)
class DoorbellBase:
    id: str
    public_key: dict[str, Any]
    ring_key: str | None


async def by_key(conn: Connection, thumbprint: str) -> DoorbellBase | None:
    """The base whose key this is, to check a keepalive's signature."""
    cur = await conn.execute(
        "SELECT id, public_key, ring_key FROM base WHERE key_thumbprint = %s",
        (thumbprint,),
    )
    row = await cur.fetchone()
    return DoorbellBase(**row) if row else None


async def rang(conn: Connection, *, base_id: str, now: datetime) -> None:
    """A keepalive the Doorbell server relayed and the Portal verified: a
    sign of life."""
    await conn.execute(
        "UPDATE base SET last_seen_at = %s, last_doorbell_at = %s WHERE id = %s",
        (now, now, base_id),
    )


async def ring_key(conn: Connection, base_id: str) -> str:
    """The base's ring key, made the first time it is asked for."""
    cur = await conn.execute(
        "UPDATE base SET ring_key = coalesce(ring_key, %s) WHERE id = %s"
        " RETURNING ring_key",
        (doorbell.new_ring_key(), base_id),
    )
    row = await cur.fetchone()
    assert row is not None
    return str(row["ring_key"])


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
