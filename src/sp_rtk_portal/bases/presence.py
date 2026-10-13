"""Signs of life from a Claimed base's agent: polls, Check-ins, Doorbell
keepalives (relayed by the Doorbell server), and 426s.

Each finds the base by its key's thumbprint (``None``: no such base, the
agent gets 401 ``unclaimed``) and records when it was seen, from which public
IP (``CF-Connecting-IP``) and with which protocol version.
"""

from __future__ import annotations

import json
from dataclasses import KW_ONLY, dataclass
from datetime import datetime
from typing import Any

from sp_rtk_portal_protocol import CheckIn, doorbell

from sp_rtk_portal.db import Connection


@dataclass(frozen=True)
class Seen:
    base_id: str
    metered: bool
    _: KW_ONLY
    owner_account_id: int | None = None
    paused: bool = False
    was_paused: bool = False
    """Before this poll or Check-in (a change is audited)."""
    last_doorbell_at: datetime | None = None


@dataclass(frozen=True)
class Pace:
    """What sets how often a base may poll: the metered flag, and the one
    its agent last heard (it polls at that until its next reply)."""

    base_id: str
    owner_account_id: int
    metered: bool
    polled_metered: bool


async def pace(conn: Connection, thumbprint: str) -> Pace | None:
    """The base with this key (``None``: no such base)."""
    cur = await conn.execute(
        "SELECT id AS base_id, owner_account_id, metered, polled_metered"
        " FROM base WHERE key_thumbprint = %s",
        (thumbprint,),
    )
    row = await cur.fetchone()
    return Pace(**row) if row else None


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
    """A Check-in. Its ``paused`` (when the agent sends one) sets remote
    access paused as a poll does."""
    cur = await conn.execute(
        "UPDATE base SET last_seen_at = %s, last_check_in_at = %s,"
        " protocol_version = %s, public_ip = coalesce(%s::inet, public_ip),"
        " needs_upgrade = false, polled_metered = metered,"
        " software_version = %s, doorbell = %s, lan_addresses = %s,"
        " remote_paused = coalesce(%s, remote_paused)"
        " FROM (SELECT id AS old_id, remote_paused AS was_paused FROM base"
        "       WHERE key_thumbprint = %s FOR UPDATE) AS old"
        " WHERE base.id = old.old_id"
        " RETURNING id, metered, last_doorbell_at, owner_account_id,"
        " remote_paused, was_paused",
        (
            now,
            now,
            protocol_version,
            ip,
            check_in.software_version,
            check_in.doorbell,
            json.dumps([a.to_json() for a in check_in.lan_addresses]),
            check_in.paused,
            thumbprint,
        ),
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
        last_doorbell_at=row["last_doorbell_at"],
    )


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
