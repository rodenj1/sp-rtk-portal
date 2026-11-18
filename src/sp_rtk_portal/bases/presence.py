"""Signs of life from a Claimed base's agent: polls, Check-ins and 426s.

Each finds the base by its key's thumbprint (``None``: no such base, the
agent gets 401 ``unclaimed``) and records when it was seen, from which public
IP (``CF-Connecting-IP``) and with which protocol version.
"""

from __future__ import annotations

import json
from dataclasses import KW_ONLY, dataclass
from datetime import datetime

from sp_rtk_portal_protocol import CheckIn

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
        " software_version = %s, lan_addresses = %s,"
        " remote_paused = coalesce(%s, remote_paused)"
        " FROM (SELECT id AS old_id, remote_paused AS was_paused FROM base"
        "       WHERE key_thumbprint = %s FOR UPDATE) AS old"
        " WHERE base.id = old.old_id"
        " RETURNING id, metered, owner_account_id,"
        " remote_paused, was_paused",
        (
            now,
            now,
            protocol_version,
            ip,
            check_in.software_version,
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
    )


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
