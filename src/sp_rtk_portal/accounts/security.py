"""Account security: log out everywhere.

``log_out_everywhere(ctx, ...)`` ends every Portal session of the account
and every live Remote session (revoking their ``/b/`` tokens). It also runs
automatically after a password change or recovery, through the
``PasswordChanged`` hook ``LogOutEverywhere`` (registered in ``create_app``),
which keeps the session that changed the password.
"""

from __future__ import annotations

from sp_rtk_portal import audit
from sp_rtk_portal.context import PortalContext
from sp_rtk_portal.db import Connection

LOG_OUT_EVERYWHERE = "log_out_everywhere"
"""Remote session end reason (and audit kind ``audit.LOG_OUT_EVERYWHERE``)."""

BUTTON = "button"
"""Audit ``trigger``: the user pressed "Log out everywhere"."""


async def log_out_everywhere(
    ctx: PortalContext, *, account_id: int, ip: str | None
) -> None:
    """Every Portal session of the account ends, this one included."""
    async with ctx.db.connection() as conn:
        await end_portal_sessions(conn, account_id)
        await audit.record(
            conn,
            at=ctx.clock.now(),
            kind=audit.LOG_OUT_EVERYWHERE,
            account_id=account_id,
            ip=ip,
            detail={"trigger": BUTTON},
        )
    await ctx.tunnels.end_sessions(LOG_OUT_EVERYWHERE, account_id=account_id, ip=ip)


async def end_portal_sessions(
    conn: Connection, account_id: int, *, keep_hash: bytes | None = None
) -> None:
    await conn.execute(
        "DELETE FROM portal_session WHERE account_id = %s"
        " AND token_hash IS DISTINCT FROM %s",
        (account_id, keep_hash),
    )
