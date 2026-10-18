"""Sharing a base by email, and taking a Share away.

- ``share(ctx, ...)``: the Operator Shares their base with an email. A
  verified account with that email gets a Share at once; otherwise a Pending
  share waits (``Settings.pending_share_lifetime``) for the first login with
  that verified email. Either way the recipient and the base's Operator are
  emailed. Raises ``ShareRefused`` (message for the Operator).
- ``convert_pending(conn, ...)``: at login, inside the login's transaction.
- ``remove(ctx, ...)`` / ``leave(ctx, ...)``: the Operator removes a Shared
  user, or the Shared user leaves; that user's live Remote sessions on the
  base end at once (their ``/b/`` token stops working).
- ``remove_pending(ctx, ...)``: the Operator withdraws a Pending share.
- ``unclaimed``: the ``BaseEvents.on_unclaimed`` hook (registered in
  ``create_app``): Un-claim removes the base's Shares and Pending shares.

Every change is audited in its own transaction; email is sent after commit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from sp_rtk_portal import audit
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.bases.events import Unclaimed
from sp_rtk_portal.context import PortalContext
from sp_rtk_portal.db import Connection
from sp_rtk_portal.shares import store
from sp_rtk_portal.tunnel.end_reason import EndReason

NOT_OPERATOR = "Only the base's Operator can Share it."
BAD_EMAIL = "Enter an email address."
SELF = "That's your own email: you're this base's Operator."
ALREADY_SHARED = "This base is already Shared with {email}."
ALREADY_PENDING = "{email} already has a Pending share for this base."
TOO_MANY_SHARED = (
    "This base already has {limit} Shared users, the limit. Remove one first."
)
TOO_MANY_PENDING = (
    "This base already has {limit} Pending shares, the limit. Withdraw one first."
)

_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


class ShareRefused(Exception):
    """The Share wasn't made; ``str()`` says why, for the Operator."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Shared:
    """What ``share`` did: a Share, or a Pending share until ``expires_at``."""

    email: str
    pending: bool
    expires_at: datetime | None = None


def normalize_email(email: str) -> str:
    email = email.strip().lower()
    if len(email) > 254 or not _EMAIL.fullmatch(email):
        raise ShareRefused(BAD_EMAIL)
    return email


async def share(
    ctx: PortalContext, *, base_id: str, operator: Account, email: str, ip: str | None
) -> Shared:
    """Share ``base_id`` (``operator``'s) with ``email``. ``ShareRefused``
    with status 404 when the base isn't the Operator's to Share (403 when the
    caller is one of its Shared users)."""
    email = normalize_email(email)
    now = ctx.clock.now()
    s = ctx.settings
    async with ctx.db.connection() as conn:
        base = await store.lock_base(conn, base_id)
        if base is None:
            raise ShareRefused("No such base.", 404)
        if base.owner_account_id != operator.id:
            if await store.is_shared(conn, base_id, operator.id):
                raise ShareRefused(NOT_OPERATOR, 403)
            raise ShareRefused("No such base.", 404)
        if email == base.owner_email.lower():
            raise ShareRefused(SELF)
        shares, pending = await store.count(conn, base_id, now)
        recipient = await store.verified_account(conn, email)
        if recipient is not None:
            if await store.is_shared(conn, base_id, recipient):
                raise ShareRefused(ALREADY_SHARED.format(email=email))
            if shares >= s.max_shared_users_per_base:
                raise ShareRefused(
                    TOO_MANY_SHARED.format(limit=s.max_shared_users_per_base)
                )
            await store.add_share(conn, base_id, recipient, now, operator.id)
            await audit.record(
                conn,
                at=now,
                kind=audit.SHARE_ADDED,
                account_id=operator.id,
                base_id=base_id,
                ip=ip,
                detail={"shared_user": recipient, "email": email},
            )
            done = Shared(email, pending=False)
        else:
            live = {p.email for p in await store.pending_shares(conn, base_id, now)}
            if email in live:
                raise ShareRefused(ALREADY_PENDING.format(email=email))
            if pending >= s.max_pending_shares_per_base:
                raise ShareRefused(
                    TOO_MANY_PENDING.format(limit=s.max_pending_shares_per_base)
                )
            expires_at = now + s.pending_share_lifetime
            await store.add_pending(conn, base_id, email, now, expires_at, operator.id)
            await audit.record(
                conn,
                at=now,
                kind=audit.PENDING_SHARE_CREATED,
                account_id=operator.id,
                base_id=base_id,
                ip=ip,
                detail={"email": email, "expires_at": expires_at.isoformat()},
            )
            done = Shared(email, pending=True, expires_at=expires_at)
    await _email(ctx, base, operator.email, done, now)
    return done


async def convert_pending(
    conn: Connection, ctx: PortalContext, account: Account, ip: str | None
) -> int:
    """Turn the live Pending shares for ``account``'s verified email into
    Shares (bound to the account, i.e. its ``(iss, sub)``). Runs inside the
    login's transaction. A base already at its Shared-user limit keeps the
    Pending share for a later login. Returns how many converted."""
    if not account.email_verified:
        return 0
    now = ctx.clock.now()
    limit = ctx.settings.max_shared_users_per_base
    converted = 0
    for pending_id, base_id, created_by in await store.pending_for(
        conn, account.email.lower(), now
    ):
        base = await store.lock_base(conn, base_id)
        if base is None or base.owner_account_id == account.id:
            continue
        shares, _ = await store.count(conn, base_id, now)
        if shares >= limit and not await store.is_shared(conn, base_id, account.id):
            continue
        await store.delete_pending(conn, base_id, pending_id)
        await store.add_share(conn, base_id, account.id, now, created_by)
        await audit.record(
            conn,
            at=now,
            kind=audit.SHARE_ADDED,
            account_id=account.id,
            base_id=base_id,
            ip=ip,
            detail={
                "shared_user": account.id,
                "email": account.email.lower(),
                "from_pending_share": pending_id,
                "created_by": created_by,
            },
        )
        converted += 1
    return converted


async def remove(
    ctx: PortalContext,
    *,
    base_id: str,
    operator_id: int,
    account_id: int,
    ip: str | None,
) -> bool:
    """The Operator removes a Shared user. ``False``: no such Share on a
    base of theirs."""
    now = ctx.clock.now()
    async with ctx.db.connection() as conn:
        base = await store.lock_base(conn, base_id)
        if base is None or base.owner_account_id != operator_id:
            return False
        email = await store.delete_share(conn, base_id, account_id)
        if email is None:
            return False
        await audit.record(
            conn,
            at=now,
            kind=audit.SHARE_REMOVED,
            account_id=operator_id,
            base_id=base_id,
            ip=ip,
            detail={"shared_user": account_id, "email": email},
        )
        await ctx.tunnels.end_for_account(
            account_id, EndReason.UN_SHARE, base_id=base_id
        )
    return True


async def leave(
    ctx: PortalContext, *, base_id: str, account_id: int, ip: str | None
) -> bool:
    """The Shared user leaves the Share. ``False``: they had none."""
    now = ctx.clock.now()
    async with ctx.db.connection() as conn:
        email = await store.delete_share(conn, base_id, account_id)
        if email is None:
            return False
        await audit.record(
            conn,
            at=now,
            kind=audit.SHARE_LEFT,
            account_id=account_id,
            base_id=base_id,
            ip=ip,
            detail={"shared_user": account_id, "email": email},
        )
        await ctx.tunnels.end_for_account(
            account_id, EndReason.SHARE_LEFT, base_id=base_id
        )
    return True


async def remove_pending(
    ctx: PortalContext,
    *,
    base_id: str,
    operator_id: int,
    pending_id: int,
    ip: str | None,
) -> bool:
    """The Operator withdraws a Pending share. ``False``: none such."""
    now = ctx.clock.now()
    async with ctx.db.connection() as conn:
        base = await store.lock_base(conn, base_id)
        if base is None or base.owner_account_id != operator_id:
            return False
        email = await store.delete_pending(conn, base_id, pending_id)
        if email is None:
            return False
        await audit.record(
            conn,
            at=now,
            kind=audit.PENDING_SHARE_REMOVED,
            account_id=operator_id,
            base_id=base_id,
            ip=ip,
            detail={"email": email},
        )
    return True


async def unclaimed(conn: Connection, event: Unclaimed) -> None:
    """``BaseEvents`` hook: an Un-claimed base takes its Shares and Pending
    shares with it (each audited as removed by the Operator). The broker
    ends the Remote sessions after the commit."""
    for user in await store.shared_users(conn, event.base_id):
        await store.delete_share(conn, event.base_id, user.account_id)
        await audit.record(
            conn,
            at=event.at,
            kind=audit.SHARE_REMOVED,
            account_id=event.owner_account_id,
            base_id=event.base_id,
            detail={
                "shared_user": user.account_id,
                "email": user.email.lower(),
                "reason": EndReason.UN_CLAIM,
            },
        )
    for pending in await store.pending_shares(conn, event.base_id, event.at):
        await store.delete_pending(conn, event.base_id, pending.id)
        await audit.record(
            conn,
            at=event.at,
            kind=audit.PENDING_SHARE_REMOVED,
            account_id=event.owner_account_id,
            base_id=event.base_id,
            detail={"email": pending.email, "reason": EndReason.UN_CLAIM},
        )


# --- email --------------------------------------------------------------------------


def _one_line(text: str) -> str:
    return " ".join(text.split())


async def _email(
    ctx: PortalContext,
    base: store.Target,
    by: str,
    done: Shared,
    now: datetime,
) -> None:
    origin = ctx.settings.public_origin
    name = _one_line(base.name)
    body = (
        f"{by} has Shared the base station “{name}” with you on the"
        " sp-rtk-base Portal, so you can operate it remotely.\n\n"
    )
    if done.pending:
        assert done.expires_at is not None
        expires = done.expires_at.strftime("%Y-%m-%d %H:%M UTC")
        body += (
            f"To accept, create a Portal account with this email address"
            f" ({done.email}):\n{origin}/signup\n\n"
            f"Already have an account with this address? Sign in:\n{origin}/login\n\n"
            f"This Pending share expires on {expires}.\n"
        )
        kind = "A Pending share"
    else:
        body += f"It's in your list of bases:\n{origin}/\n"
        kind = "A Share"
    await ctx.mailer.send(done.email, f"{by} Shared the base “{name}” with you", body)
    notice = (
        f"{kind} of your base “{name}” was created for {done.email}"
        f" by {by} at {now.strftime('%Y-%m-%d %H:%M UTC')}.\n\n"
        f"If you didn't do this, remove it here:\n{origin}/bases/{base.id}/shares\n"
    )
    await ctx.mailer.send(
        base.owner_email, f"Your base “{name}” was Shared with {done.email}", notice
    )
