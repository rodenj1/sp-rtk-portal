"""Un-claim: the Portal forgets a base.

``BaseEvents.unclaimed`` hooks run (Shares, #94), then its record and key
go (an approved pairing and its Remote session rows with it, by cascade)
and an audit entry is written, all in one transaction. Then its live Remote
sessions end, revoking their ``/b/`` tokens, and its tunnel closes. The
agent learns it from the 401 ``unclaimed`` on its next request (or it asked
for it, with a release). A new Claim makes a new base with a new ``<id>``.
"""

from __future__ import annotations

from typing import Any, Literal

from sp_rtk_portal import audit
from sp_rtk_portal.bases.events import Unclaimed
from sp_rtk_portal.context import PortalContext
from sp_rtk_portal.db import Connection

_SELECT = "SELECT id, owner_account_id, name, key_thumbprint FROM base"


async def by_operator(
    ctx: PortalContext,
    *,
    base_id: str,
    account_id: int,
    ip: str | None,
    by: Literal["portal", "account_deleted"] = "portal",
) -> bool:
    """The Operator Un-claims their base on the Portal (``by="portal"``), or
    deletes their account (``by="account_deleted"``). ``False``: no such
    base of theirs (a Shared user's attempt included)."""
    async with ctx.db.connection() as conn:
        cur = await conn.execute(
            _SELECT + " WHERE id = %s AND owner_account_id = %s FOR UPDATE",
            (base_id, account_id),
        )
        row = await cur.fetchone()
        if row is None:
            return False
        await _forgotten(ctx, conn, row, by=by, ip=ip)
    await ctx.tunnels.forget_base(base_id)
    return True


async def by_base(ctx: PortalContext, *, thumbprint: str, ip: str | None) -> str | None:
    """The base released itself (a local Un-claim), signed with its key.
    Returns its ``<id>``, or ``None`` if no base has that key."""
    async with ctx.db.connection() as conn:
        cur = await conn.execute(
            _SELECT + " WHERE key_thumbprint = %s FOR UPDATE", (thumbprint,)
        )
        row = await cur.fetchone()
        if row is None:
            return None
        await _forgotten(ctx, conn, row, by="base", ip=ip)
    await ctx.tunnels.forget_base(row["id"])
    return str(row["id"])


async def _forgotten(
    ctx: PortalContext,
    conn: Connection,
    row: dict[str, Any],
    *,
    by: Literal["base", "portal", "account_deleted"],
    ip: str | None,
) -> None:
    """Hooks first (while the base row still exists, so rows referencing it
    can go), then the base itself, then the audit entry."""
    now = ctx.clock.now()
    await ctx.base_events.unclaimed(
        conn,
        Unclaimed(
            base_id=row["id"], owner_account_id=row["owner_account_id"], at=now, by=by
        ),
    )
    await conn.execute("DELETE FROM base WHERE id = %s", (row["id"],))
    await audit.record(
        conn,
        at=now,
        kind=audit.UNCLAIM,
        account_id=row["owner_account_id"],
        base_id=row["id"],
        ip=ip,
        detail={"by": by, "name": row["name"], "key_thumbprint": row["key_thumbprint"]},
    )
