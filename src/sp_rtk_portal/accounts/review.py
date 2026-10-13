"""The review of recent Shares after a password change or recovery.

Whoever knew the old password may have Shared the user's bases with
themselves. After a change or recovery (the ``PasswordChanged`` hook
``review_due``, registered in ``create_app``) the Portal lands the user on
``/account/review``: the Shares and Pending shares created from their account
in the last ``WINDOW``, each with a one-click remove. It can be skipped, but
every login lands there again until the user marks it seen.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sp_rtk_portal.accounts.events import PasswordChanged
from sp_rtk_portal.db import Connection

PATH = "/account/review"
WINDOW = timedelta(days=30)


@dataclass(frozen=True)
class RecentShare:
    base_id: str
    base_name: str
    account_id: int
    email: str
    created_at: datetime


@dataclass(frozen=True)
class RecentPendingShare:
    id: int
    base_id: str
    base_name: str
    email: str
    created_at: datetime
    expires_at: datetime


async def review_due(conn: Connection, event: PasswordChanged) -> None:
    """The ``PasswordChanged`` hook."""
    await conn.execute(
        "UPDATE account SET share_review_due = true WHERE id = %s",
        (event.account_id,),
    )


async def is_due(conn: Connection, account_id: int) -> bool:
    cur = await conn.execute(
        "SELECT share_review_due FROM account WHERE id = %s", (account_id,)
    )
    row = await cur.fetchone()
    return bool(row and row["share_review_due"])


async def seen(conn: Connection, account_id: int) -> None:
    await conn.execute(
        "UPDATE account SET share_review_due = false WHERE id = %s", (account_id,)
    )


async def recent_shares(
    conn: Connection, account_id: int, now: datetime
) -> list[RecentShare]:
    cur = await conn.execute(
        "SELECT s.base_id, b.name AS base_name, s.account_id, a.email, s.created_at"
        " FROM share s JOIN base b ON b.id = s.base_id"
        " JOIN account a ON a.id = s.account_id"
        " WHERE s.created_by = %s AND s.created_at > %s"
        " ORDER BY s.created_at DESC, s.base_id",
        (account_id, now - WINDOW),
    )
    return [RecentShare(**row) for row in await cur.fetchall()]


async def recent_pending_shares(
    conn: Connection, account_id: int, now: datetime
) -> list[RecentPendingShare]:
    cur = await conn.execute(
        "SELECT p.id, p.base_id, b.name AS base_name, p.email, p.created_at,"
        " p.expires_at FROM pending_share p JOIN base b ON b.id = p.base_id"
        " WHERE p.created_by = %s AND p.created_at > %s AND p.expires_at > %s"
        " ORDER BY p.created_at DESC, p.id",
        (account_id, now - WINDOW, now),
    )
    return [RecentPendingShare(**row) for row in await cur.fetchall()]
