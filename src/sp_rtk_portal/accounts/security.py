"""Account security: logging out, here and everywhere.

``log_out(ctx, ...)`` ends one Portal session and, with it, every live
Remote session of its account (revoking their ``/b/`` tokens; a Remote
session is per account, shared by all its browsers). ``log_out_everywhere``
ends every Portal session of the account too. It also runs automatically
after a password change or recovery, through the ``PasswordChanged`` hook
``LogOutEverywhere`` (registered in ``create_app``), which keeps the session
that changed the password.
"""

from __future__ import annotations

from sp_rtk_portal import audit
from sp_rtk_portal.accounts import events, sessions
from sp_rtk_portal.accounts.events import PasswordChanged
from sp_rtk_portal.context import PortalContext
from sp_rtk_portal.db import Connection
from sp_rtk_portal.tunnel.end_reason import EndReason

BUTTON = "button"
"""Audit ``trigger``: the user pressed "Log out everywhere"."""
TRIGGERS = {events.CHANGE: "password_change", events.RECOVERY: "password_recovery"}
"""Audit ``trigger`` after a password change or recovery."""


async def log_out(ctx: PortalContext, *, token: str, ip: str | None) -> None:
    """The Portal session behind ``token`` ends (nothing happens if there is
    none), and so do its account's Remote sessions."""
    async with ctx.db.connection() as conn:
        account_id = await sessions.end(conn, token)
        if account_id is not None:
            await ctx.tunnels.end_for_account(account_id, EndReason.LOGGED_OUT, ip=ip)


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
        await ctx.tunnels.end_for_account(
            account_id, EndReason.LOG_OUT_EVERYWHERE, ip=ip
        )


async def end_portal_sessions(
    conn: Connection, account_id: int, *, keep_hash: bytes | None = None
) -> None:
    await conn.execute(
        "DELETE FROM portal_session WHERE account_id = %s"
        " AND token_hash IS DISTINCT FROM %s",
        (account_id, keep_hash),
    )


class LogOutEverywhere:
    """The ``PasswordChanged`` hook: whoever held the old password is out.

    Every Portal session but the one that changed the password ends (after a
    recovery, all of them: the recovering browser's session starts after
    this), and every Remote session. Runs inside the change's transaction;
    the Remote sessions end at once, whatever becomes of it (failing safe).
    """

    def __init__(self, ctx: PortalContext) -> None:
        self._ctx = ctx

    async def __call__(self, conn: Connection, event: PasswordChanged) -> None:
        keep = event.keep_session_token
        await end_portal_sessions(
            conn,
            event.account_id,
            keep_hash=sessions.token_hash(keep) if keep else None,
        )
        await audit.record(
            conn,
            at=event.at,
            kind=audit.LOG_OUT_EVERYWHERE,
            account_id=event.account_id,
            ip=event.ip,
            detail={"trigger": TRIGGERS[event.how]},
        )
        await self._ctx.tunnels.end_for_account(
            event.account_id, EndReason.LOG_OUT_EVERYWHERE, ip=event.ip
        )
