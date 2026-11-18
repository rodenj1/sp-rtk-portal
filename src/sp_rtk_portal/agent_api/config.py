"""The agent config block, the notices and the latest sp-rtk-base release:
what the Portal owner sets on ``/settings`` and every poll and Check-in reply
carries.

The config is revisioned: each save is a new row with the next revision, and
an agent applies a block only when the revision differs from its own. With no
row yet the Portal serves the built-in defaults as revision 1.

The Portal refuses a config the agent would ignore (a timing out of range, a
tunnel URL that isn't ``wss://`` on the Portal's own host); the agent checks
the same things again, since it doesn't trust the Portal with its network.
A row saved before the Doorbell was dropped (ADR 0006) still names a Doorbell
host and port: reading it ignores them, as it ignores any unknown field.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from sp_rtk_portal_protocol import TUNNEL_PATH, AgentConfig, Notice

from sp_rtk_portal.config import Settings
from sp_rtk_portal.db import Connection

FIRST_REVISION = 1

RANGES: dict[str, tuple[int, int]] = {
    "poll_interval": (10, 3600),
    "metered_poll_interval": (10, 3600),
    "check_in_interval": (60, 86400),
    "tunnel_idle_timeout": (10, 86400),
    "tunnel_hard_cap": (60, 86400),
    "lease_length": (60, 3600),
    "lease_renewal_interval": (10, 600),
}
"""Seconds; the agent ignores a value outside these (sp-rtk-base
``portal_agent.agent_config.RANGES``). The lease ones are the Session bar's
alone: the agent has no range for them."""


class ConfigRefused(Exception):
    """The values aren't a config the agent would use. Message for the owner."""


def default_tunnel_url(settings: Settings) -> str:
    return f"wss://{urlsplit(settings.public_origin).netloc}{TUNNEL_PATH}"


def defaults(settings: Settings) -> AgentConfig:
    return AgentConfig(revision=FIRST_REVISION, tunnel_url=default_tunnel_url(settings))


async def current(conn: Connection, settings: Settings) -> AgentConfig:
    cur = await conn.execute(
        "SELECT config FROM agent_config ORDER BY revision DESC LIMIT 1"
    )
    row = await cur.fetchone()
    if row is None:
        return defaults(settings)
    return AgentConfig.from_json(row["config"])


def updated(
    base: AgentConfig, values: dict[str, Any], settings: Settings
) -> AgentConfig:
    """``base`` with ``values`` (form strings) applied and checked. Raises
    :class:`ConfigRefused`."""
    fields = {f.name for f in dataclasses.fields(AgentConfig)} - {"revision"}
    changes: dict[str, Any] = {}
    for name, raw in values.items():
        if name not in fields:
            continue
        text = "" if raw is None else str(raw).strip()
        if name in RANGES:
            try:
                changes[name] = int(text)
            except ValueError:
                raise ConfigRefused(f"{name} must be a whole number") from None
        else:
            changes[name] = text
    config = dataclasses.replace(base, **changes)
    check(config, settings)
    return config


def check(config: AgentConfig, settings: Settings) -> None:
    for name, (low, high) in RANGES.items():
        value = getattr(config, name)
        if not low <= value <= high:
            raise ConfigRefused(f"{name} must be between {low} and {high} seconds")
    if config.lease_renewal_interval >= config.lease_length:
        raise ConfigRefused("lease_renewal_interval must be shorter than lease_length")
    if config.tunnel_url:
        portal = urlsplit(settings.public_origin)
        url = urlsplit(config.tunnel_url)
        if url.scheme != "wss" or url.netloc != portal.netloc:
            raise ConfigRefused(
                f"The tunnel URL must be wss://{portal.netloc}/...: an agent "
                "ignores any other"
            )


async def save(
    conn: Connection, config: AgentConfig, *, now: datetime, account_id: int
) -> AgentConfig:
    """Store ``config`` as the next revision; returns it with that revision."""
    cur = await conn.execute(
        "SELECT coalesce(max(revision), %s) AS r FROM agent_config",
        (FIRST_REVISION,),
    )
    row = await cur.fetchone()
    assert row is not None
    saved = dataclasses.replace(config, revision=row["r"] + 1)
    await conn.execute(
        "INSERT INTO agent_config (revision, config, created_at, created_by)"
        " VALUES (%s, %s, %s, %s)",
        (saved.revision, json.dumps(saved.to_json()), now, account_id),
    )
    return saved


# --- Notices -------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class StoredNotice:
    id: int
    text: str
    created_at: datetime


async def notices(conn: Connection) -> list[StoredNotice]:
    cur = await conn.execute("SELECT id, text, created_at FROM notice ORDER BY id")
    return [StoredNotice(**row) for row in await cur.fetchall()]


async def wire_notices(conn: Connection) -> list[Notice]:
    return [Notice(text=n.text) for n in await notices(conn)]


async def add_notice(conn: Connection, text: str, now: datetime) -> None:
    await conn.execute(
        "INSERT INTO notice (text, created_at) VALUES (%s, %s)", (text, now)
    )


async def remove_notice(conn: Connection, notice_id: int) -> bool:
    cur = await conn.execute("DELETE FROM notice WHERE id = %s", (notice_id,))
    return cur.rowcount > 0


# --- The latest sp-rtk-base release -------------------------------------------

LATEST_RELEASE = "latest_release"


async def latest_release(conn: Connection) -> str | None:
    cur = await conn.execute(
        "SELECT value FROM portal_setting WHERE key = %s", (LATEST_RELEASE,)
    )
    row = await cur.fetchone()
    return row["value"] if row else None


async def set_latest_release(conn: Connection, version: str) -> None:
    await conn.execute(
        "INSERT INTO portal_setting (key, value) VALUES (%s, %s)"
        " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        (LATEST_RELEASE, version),
    )


def parse_version(version: str) -> tuple[int, ...] | None:
    """``"0.11.2"`` -> ``(0, 11, 2)``; ``None`` if it isn't plain numbers."""
    parts = version.strip().removeprefix("v").split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def update_available(installed: str, latest: str | None) -> bool:
    if latest is None:
        return False
    have, newest = parse_version(installed), parse_version(latest)
    return have is not None and newest is not None and newest > have
