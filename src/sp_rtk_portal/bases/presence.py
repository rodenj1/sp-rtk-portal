"""Signs of life from a Claimed base's agent: polls, Check-ins, its held
tunnel and 426s.

Each poll, Check-in or 426 finds the base by its key's thumbprint (``None``:
no such base, the agent gets 401 ``unclaimed``) and records when it was
seen, from which public IP (``CF-Connecting-IP``) and with which protocol
version.

The base's connection mode (``holding``, ``reconnecting``, ``polling``)
follows its tunnel: :func:`tunnel_held` when it opens a held tunnel,
:func:`tunnel_dropped` when that closes. A poll or Check-in from an agent
that doesn't hold its tunnel (protocol version 1) makes it ``polling``, and
so does a Check-in from a version 2 agent that says it fell back to polling
(ticket #209) until its tunnel is held again.
"""

from __future__ import annotations

import json
from dataclasses import KW_ONLY, dataclass, field
from datetime import datetime

from sp_rtk_portal_protocol import (
    HOLDING_VERSION,
    MODE_HOLDING,
    MODE_POLLING,
    MODE_RECONNECTING,
    CheckIn,
    ConnectionMode,
)

from sp_rtk_portal.db import Connection

_MODE = (
    "connection_mode = CASE WHEN %(version)s < %(holding_version)s"
    " OR %(mode)s::text = %(polling)s THEN %(polling)s ELSE connection_mode END"
)
"""A poll or Check-in's connection mode: ``polling`` from an agent that
doesn't hold its tunnel, or one that says it fell back (``mode``); else it
follows the tunnel."""


def _mode_params(version: int, mode: ConnectionMode | None) -> dict[str, object]:
    return {
        "version": version,
        "holding_version": HOLDING_VERSION,
        "mode": mode,
        "polling": MODE_POLLING,
    }


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
    its agent last heard (it polls at that until its next reply); and what
    its last Check-in said, to tell a Check-in with news from a repeat."""

    base_id: str
    owner_account_id: int
    metered: bool
    polled_metered: bool
    remote_paused: bool = False
    software_version: str = ""
    lan_addresses: list[dict[str, object]] = field(default_factory=list)

    def news_in(self, check_in: CheckIn) -> bool:
        """``check_in`` changes what the Portal knows: a pause or resume, a
        new software version or new LAN addresses."""
        return (
            (check_in.paused is not None and check_in.paused != self.remote_paused)
            or check_in.software_version != self.software_version
            or [a.to_json() for a in check_in.lan_addresses] != self.lan_addresses
        )


async def pace(conn: Connection, thumbprint: str) -> Pace | None:
    """The base with this key (``None``: no such base)."""
    cur = await conn.execute(
        "SELECT id AS base_id, owner_account_id, metered, polled_metered,"
        " remote_paused, software_version, lan_addresses"
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
        "UPDATE base SET last_seen_at = %(now)s, protocol_version = %(version)s,"
        " public_ip = coalesce(%(ip)s::inet, public_ip), needs_upgrade = false,"
        f" polled_metered = metered, remote_paused = %(paused)s, {_MODE}"
        " FROM (SELECT id AS old_id, remote_paused AS was_paused FROM base"
        "       WHERE key_thumbprint = %(thumbprint)s FOR UPDATE) AS old"
        " WHERE base.id = old.old_id"
        " RETURNING id, metered, owner_account_id, remote_paused, was_paused",
        {
            "now": now,
            "ip": ip,
            "paused": paused,
            "thumbprint": thumbprint,
            **_mode_params(protocol_version, None),
        },
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
        "UPDATE base SET last_seen_at = %(now)s, last_check_in_at = %(now)s,"
        " protocol_version = %(version)s,"
        " public_ip = coalesce(%(ip)s::inet, public_ip),"
        " needs_upgrade = false, polled_metered = metered,"
        " software_version = %(software)s, lan_addresses = %(lan)s,"
        f" remote_paused = coalesce(%(paused)s, remote_paused), {_MODE}"
        " FROM (SELECT id AS old_id, remote_paused AS was_paused FROM base"
        "       WHERE key_thumbprint = %(thumbprint)s FOR UPDATE) AS old"
        " WHERE base.id = old.old_id"
        " RETURNING id, metered, owner_account_id,"
        " remote_paused, was_paused",
        {
            "now": now,
            "ip": ip,
            "software": check_in.software_version,
            "lan": json.dumps([a.to_json() for a in check_in.lan_addresses]),
            "paused": check_in.paused,
            "thumbprint": thumbprint,
            **_mode_params(protocol_version, check_in.mode),
        },
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


async def tunnel_held(conn: Connection, base_id: str, now: datetime) -> None:
    """The base opened a held tunnel: it's ``holding``, and seen now."""
    await conn.execute(
        "UPDATE base SET connection_mode = %s,"
        " last_seen_at = greatest(last_seen_at, %s) WHERE id = %s",
        (MODE_HOLDING, now, base_id),
    )


async def heard(conn: Connection, base_id: str, now: datetime) -> None:
    """The base's held tunnel carried something (a ping, a Check-in): it's
    seen now."""
    await conn.execute(
        "UPDATE base SET last_seen_at = greatest(last_seen_at, %s) WHERE id = %s",
        (now, base_id),
    )


async def tunnel_dropped(conn: Connection, base_id: str, last_heard: datetime) -> None:
    """The base's held tunnel closed, last heard from at ``last_heard``:
    it's ``reconnecting`` (online for a grace period after that)."""
    await conn.execute(
        "UPDATE base SET connection_mode = %s,"
        " last_seen_at = greatest(last_seen_at, %s)"
        " WHERE id = %s AND connection_mode = %s",
        (MODE_RECONNECTING, last_heard, base_id, MODE_HOLDING),
    )


async def tunnels_gone(conn: Connection) -> int:
    """The Portal (re)started: no tunnel is held any more. Returns how many
    bases were holding one."""
    cur = await conn.execute(
        "UPDATE base SET connection_mode = %s WHERE connection_mode = %s",
        (MODE_RECONNECTING, MODE_HOLDING),
    )
    return cur.rowcount
