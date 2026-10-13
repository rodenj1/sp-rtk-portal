"""Account deletion.

``preview`` lists the bases deletion will Un-claim. ``delete_account``:

1. deactivates the Authentik user (admin API). If Authentik refuses, it
   raises ``AuthentikFailedClosed`` and nothing has changed;
2. in ONE transaction: Un-claims every base the account Claimed
   (``unclaim.forget_owned`` with ``by="account_deleted"``: the Shares on
   them go, agents get 401 ``unclaimed``), removes the Shares the account
   holds on other bases (audited ``share_left`` with ``reason:
   account_deleted``), ends every Portal session, marks the account deleted
   and audits ``account_deleted``. If any of it fails none of it sticks:
   the user is still signed in and can try again (deactivating an inactive
   Authentik user again is harmless);
3. forgets the Un-claimed bases' tunnels and Remote sessions, and ends the
   account's remaining Remote sessions (reason ``account_deleted``).

The account row stays (``deleted_at``) so audit entries keep their "who".
Pending shares addressed to the email stay: they convert only for an account
with that verified email, which a deactivated user can't sign in to.
"""

from __future__ import annotations

from sp_rtk_portal import audit
from sp_rtk_portal.accounts.security import end_portal_sessions
from sp_rtk_portal.accounts.store import Account, authentik_sub
from sp_rtk_portal.bases import store as bases
from sp_rtk_portal.bases import unclaim
from sp_rtk_portal.bases.events import BY_ACCOUNT_DELETION
from sp_rtk_portal.context import PortalContext
from sp_rtk_portal.db import Connection
from sp_rtk_portal.shares import store as shares
from sp_rtk_portal.tunnel.end_reason import EndReason


async def preview(conn: Connection, account_id: int) -> list[bases.BaseSummary]:
    """The bases deleting the account will Un-claim."""
    return await bases.owned_by(conn, account_id)


async def delete_account(ctx: PortalContext, account: Account, ip: str | None) -> None:
    async with ctx.db.connection() as conn:
        sub = await authentik_sub(conn, account.id)
    await ctx.authentik.deactivate_user(sub)

    now = ctx.clock.now()
    unclaimed: list[str] = []
    # One transaction: if anything fails, nothing here sticks and the user
    # (still signed in; deactivating again is harmless) can try again.
    async with ctx.db.connection() as conn:
        for base in await bases.owned_by(conn, account.id):
            if await unclaim.forget_owned(
                ctx,
                conn,
                base_id=base.id,
                account_id=account.id,
                ip=ip,
                by=BY_ACCOUNT_DELETION,
            ):
                unclaimed.append(base.id)
        cur = await conn.execute(
            "SELECT base_id FROM share WHERE account_id = %s ORDER BY base_id",
            (account.id,),
        )
        for row in await cur.fetchall():
            email = await shares.delete_share(conn, row["base_id"], account.id)
            if email is None:
                continue
            await audit.record(
                conn,
                at=now,
                kind=audit.SHARE_LEFT,
                account_id=account.id,
                base_id=row["base_id"],
                ip=ip,
                detail={
                    "shared_user": account.id,
                    "email": email,
                    "reason": EndReason.ACCOUNT_DELETED,
                },
            )
        await end_portal_sessions(conn, account.id)
        await conn.execute(
            "UPDATE account SET deleted_at = %s, share_review_due = false"
            " WHERE id = %s",
            (now, account.id),
        )
        await audit.record(
            conn,
            at=now,
            kind=audit.ACCOUNT_DELETED,
            account_id=account.id,
            ip=ip,
            detail={"email": account.email, "unclaimed": unclaimed},
        )
    for base_id in unclaimed:
        await ctx.tunnels.forget_base(base_id)
    await ctx.tunnels.end_sessions(
        EndReason.ACCOUNT_DELETED, account_id=account.id, ip=ip
    )
