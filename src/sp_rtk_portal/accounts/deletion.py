"""Account deletion.

``preview`` lists the bases deletion will Un-claim. Deletion runs Authentik's
unenrollment flow as the user (ADR 0003), in three steps:

1. ``start``: the flow proves the password, the deny stage (only
   ``portal-users``) and the TOTP code if the account has one
   (``Authentik.start_deletion``, then ``submit_code``), and stops at its
   confirmation, right before its user delete stage. The flow must be acting
   on this account's own Authentik user (checked by uuid). A wrong password
   or code, a refusal or anything unexpected: nothing is deleted;
2. ``delete_account``, in ONE transaction: Un-claims every base the account
   Claimed (``unclaim.forget_owned`` with ``by="account_deleted"``: the
   Shares on them go, agents get 401 ``unclaimed``), removes the Shares the
   account holds on other bases (audited ``share_left`` with ``reason:
   account_deleted``), ends every Portal session, marks the account deleted
   and audits ``account_deleted``. If any of it fails none of it sticks and
   the Authentik user is untouched: the user, still signed in, can try again.
   After the commit it forgets the Un-claimed bases' tunnels and ends the
   account's Remote sessions (reason ``account_deleted``);
3. then the flow is confirmed, which deletes the Authentik user, and the
   admin API must no longer find it. If that fails, the Portal's data is
   already gone and the Authentik user remains: logged as an ERROR naming the
   user's uuid and audited ``account_deletion_incomplete``. The user is told
   to retry: signing in again with the same email and password gives them
   their (now empty) account back, and deleting it again removes the sign-in.
   The owner can also delete that user in Authentik by hand.

The account row stays (``deleted_at``) so audit entries keep their "who". A
new sign-up with the same email is a new Authentik user (a new ``sub``), so
a new account; tombstoned accounts are never matched by email. Pending shares
addressed to the email stay, and convert for that new account.
"""

from __future__ import annotations

import logging

from sp_rtk_portal import audit
from sp_rtk_portal.accounts.authentik import FlowAttempt, Outcome
from sp_rtk_portal.accounts.security import end_portal_sessions
from sp_rtk_portal.accounts.store import Account, authentik_sub
from sp_rtk_portal.bases import store as bases
from sp_rtk_portal.bases import unclaim
from sp_rtk_portal.bases.events import BY_ACCOUNT_DELETION
from sp_rtk_portal.context import PortalContext
from sp_rtk_portal.db import Connection
from sp_rtk_portal.shares import store as shares
from sp_rtk_portal.tunnel.end_reason import EndReason

log = logging.getLogger(__name__)


async def preview(conn: Connection, account_id: int) -> list[bases.BaseSummary]:
    """The bases deleting the account will Un-claim."""
    return await bases.owned_by(conn, account_id)


async def start(
    ctx: PortalContext, account: Account, password: str, ip: str | None
) -> tuple[FlowAttempt, Outcome]:
    """Step 1: prove the credentials. Gives ``ReadyToDelete``, ``NeedsTotp``
    or ``Rejected``; raises ``AuthentikFailedClosed``."""
    async with ctx.db.connection() as conn:
        sub = await authentik_sub(conn, account.id)
    attempt, outcome = await ctx.authentik.start_deletion(
        account.email, password, ip, sub
    )
    attempt.account_id = account.id
    return attempt, outcome


async def delete_account(
    ctx: PortalContext, account: Account, attempt: FlowAttempt, ip: str | None
) -> bool:
    """Steps 2 and 3, once ``attempt`` is ``ReadyToDelete``. True if the
    Authentik user is gone too, False if only the Portal's data is."""
    async with ctx.db.connection() as conn:
        sub = await authentik_sub(conn, account.id)
    now = ctx.clock.now()
    unclaimed: list[str] = []
    # One transaction: if anything fails, nothing here sticks, the Authentik
    # user is untouched, and the user (still signed in) can try again.
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
        await ctx.tunnels.end_for_account(account.id, EndReason.ACCOUNT_DELETED, ip=ip)
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
    try:
        await ctx.authentik.finish_deletion(attempt, sub)
    except Exception as e:
        log.error(
            "account %s: Portal data deleted, but Authentik user %s (%s) was NOT:"
            " %r. The user can sign in again and delete again, or delete that"
            " user in Authentik.",
            account.id,
            sub,
            account.email,
            e,
        )
        async with ctx.db.connection() as conn:
            await audit.record(
                conn,
                at=ctx.clock.now(),
                kind=audit.ACCOUNT_DELETION_INCOMPLETE,
                account_id=account.id,
                ip=ip,
                detail={"email": account.email, "sub": sub, "error": str(e)},
            )
        return False
    return True
