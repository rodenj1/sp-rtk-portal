"""Possible copy (ticket #98): a base key used from two places at once.

Every sign of life with a trusted client IP (poll, Check-in, Doorbell
keepalive) is shown to :class:`CopyWatch`. It remembers, per base, the runs
of consecutive requests from one IP over the last ``possible_copy_window``.
A request from an IP that had an earlier run, with a run from another IP
since (A, B, A), is interleaving: two devices hold the key. A base that
moves (A, then only B) never interleaves. A "place" is an IPv4 address or
an IPv6 /64 (privacy addresses rotate within it), and the two families are
watched apart: a dual-stack base switching between them is one device.

The first time, :func:`flag` marks the base, writes an audit entry and
emails its Operator. Nothing is blocked. The watch is in memory (one Portal
process); a restart forgets recent runs, so it may notice a copy a few
minutes later, never wrongly.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from sp_rtk_portal import audit

if TYPE_CHECKING:
    from sp_rtk_portal.context import PortalContext

log = logging.getLogger(__name__)

_MAX_RUNS = 16
"""Runs kept per base: plenty to see A, B, A within the window."""


@dataclass
class _Run:
    place: str
    ip: str
    last_at: datetime


def _place(ip: str) -> tuple[int, str]:
    """``(IP version, place)``."""
    addr = ipaddress.ip_address(ip)
    if addr.version == 6:
        return 6, str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return 4, str(addr)


class CopyWatch:
    def __init__(self) -> None:
        self._runs: dict[tuple[str, int], list[_Run]] = {}
        self._flagged: set[str] = set()

    def seen(
        self, base_id: str, ip: str, now: datetime, window: timedelta
    ) -> tuple[str, str] | None:
        """A sign of life from ``ip``. Returns ``(other IP, ip)`` when it
        interleaves with another place within ``window`` (once per base)."""
        version, place = _place(ip)
        key = (base_id, version)
        runs = [r for r in self._runs.get(key, []) if r.last_at >= now - window]
        if runs and runs[-1].place == place:
            runs[-1].ip, runs[-1].last_at = ip, now
            self._runs[key] = runs
            return None
        interleaved = (
            (runs[-1].ip, ip)
            if any(r.place == place for r in runs) and base_id not in self._flagged
            else None
        )
        runs.append(_Run(place, ip, now))
        self._runs[key] = runs[-_MAX_RUNS:]
        if interleaved:
            self._flagged.add(base_id)
        self._sweep(now, window)
        return interleaved

    def _sweep(self, now: datetime, window: timedelta) -> None:
        if len(self._runs) < 1024:
            return
        for key, runs in list(self._runs.items()):
            if runs[-1].last_at < now - window:
                del self._runs[key]


async def watch(ctx: PortalContext, base_id: str, ip: str | None) -> None:
    """Show the watch a sign of life; flag the base when it interleaves.
    Untrusted requests (no client IP) are never counted."""
    if ip is None:
        return
    now = ctx.clock.now()
    ips = ctx.copies.seen(base_id, ip, now, ctx.settings.possible_copy_window)
    if ips is not None:
        await flag(ctx, base_id, ips, now)


async def flag(
    ctx: PortalContext, base_id: str, ips: tuple[str, str], now: datetime
) -> None:
    async with ctx.db.connection() as conn:
        cur = await conn.execute(
            "UPDATE base SET possible_copy_at = %s, possible_copy_ips = %s"
            " WHERE id = %s AND possible_copy_at IS NULL"
            " RETURNING name, owner_account_id,"
            " (SELECT email FROM account WHERE id = owner_account_id) AS email",
            (now, list(ips), base_id),
        )
        row = await cur.fetchone()
        if row is None:
            return  # gone, or flagged before (e.g. before a restart)
        await audit.record(
            conn,
            at=now,
            kind=audit.POSSIBLE_COPY,
            account_id=row["owner_account_id"],
            base_id=base_id,
            ip=ips[1],
            detail={"ips": list(ips)},
        )
    log.warning("possible copy of base %s: polls from %s and %s", base_id, *ips)
    await ctx.mailer.send(row["email"], *_email(row["name"], ips, ctx))


def _email(name: str, ips: tuple[str, str], ctx: PortalContext) -> tuple[str, str]:
    name = " ".join(name.split())  # no newlines in a subject
    minutes = int(ctx.settings.possible_copy_window.total_seconds() // 60) or 1
    subject = f"Possible copy of your base {name}"
    body = (
        f"Your base {name} contacted the Portal from two public IP addresses,"
        f" {ips[0]} and {ips[1]}, taking turns within {minutes} minutes.\n\n"
        "That usually means its SD card was copied: two devices are using the"
        " same base key. The Portal has not blocked anything.\n\n"
        "If you didn't copy it, Un-claim the base on the Portal and Claim it"
        " again from its own Portal page. That gives it a new key, and the"
        " copy can no longer reach the Portal as your base.\n\n"
        f"Your bases: {ctx.settings.public_origin}/\n"
    )
    return subject, body
