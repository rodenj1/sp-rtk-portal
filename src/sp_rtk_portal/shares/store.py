"""Share and Pending share rows. Plain SQL; callers own the transaction."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sp_rtk_portal.db import Connection


@dataclass(frozen=True)
class SharedUser:
    account_id: int
    email: str
    created_at: datetime


@dataclass(frozen=True)
class PendingShare:
    id: int
    email: str
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class Target:
    """A base as the sharing code needs it, locked for the transaction."""

    id: str
    name: str
    owner_account_id: int
    owner_email: str


async def lock_base(conn: Connection, base_id: str) -> Target | None:
    """The base, row-locked so concurrent Shares count limits one at a time."""
    cur = await conn.execute(
        "SELECT base.id, base.name, base.owner_account_id,"
        " account.email AS owner_email"
        " FROM base JOIN account ON account.id = base.owner_account_id"
        " WHERE base.id = %s FOR UPDATE OF base",
        (base_id,),
    )
    row = await cur.fetchone()
    return Target(**row) if row else None


async def verified_account(conn: Connection, email: str) -> int | None:
    """The account whose verified email is ``email`` (the latest to sign in,
    should two Authentik users share one address). Never a deleted one: a
    new sign-up with that email is a new account."""
    cur = await conn.execute(
        "SELECT id FROM account WHERE lower(email) = %s AND email_verified"
        " AND deleted_at IS NULL"
        " ORDER BY last_login_at DESC LIMIT 1",
        (email,),
    )
    row = await cur.fetchone()
    return int(row["id"]) if row else None


async def shared_users(conn: Connection, base_id: str) -> list[SharedUser]:
    cur = await conn.execute(
        "SELECT share.account_id, account.email, share.created_at"
        " FROM share JOIN account ON account.id = share.account_id"
        " WHERE share.base_id = %s ORDER BY lower(account.email)",
        (base_id,),
    )
    return [SharedUser(**row) for row in await cur.fetchall()]


async def pending_shares(
    conn: Connection, base_id: str, now: datetime
) -> list[PendingShare]:
    """The base's Pending shares that haven't expired."""
    cur = await conn.execute(
        "SELECT id, email, created_at, expires_at FROM pending_share"
        " WHERE base_id = %s AND expires_at > %s ORDER BY email",
        (base_id, now),
    )
    return [PendingShare(**row) for row in await cur.fetchall()]


async def is_shared(conn: Connection, base_id: str, account_id: int) -> bool:
    cur = await conn.execute(
        "SELECT 1 FROM share WHERE base_id = %s AND account_id = %s",
        (base_id, account_id),
    )
    return await cur.fetchone() is not None


async def add_share(
    conn: Connection, base_id: str, account_id: int, now: datetime, by: int | None
) -> None:
    await conn.execute(
        "INSERT INTO share (base_id, account_id, created_at, created_by)"
        " VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
        (base_id, account_id, now, by),
    )


async def delete_share(conn: Connection, base_id: str, account_id: int) -> str | None:
    """Remove the Share; the Shared user's email, or ``None`` if there was none."""
    cur = await conn.execute(
        "DELETE FROM share USING account"
        " WHERE share.base_id = %s AND share.account_id = %s"
        "   AND account.id = share.account_id"
        " RETURNING account.email",
        (base_id, account_id),
    )
    row = await cur.fetchone()
    return str(row["email"]) if row else None


async def add_pending(
    conn: Connection,
    base_id: str,
    email: str,
    now: datetime,
    expires_at: datetime,
    by: int | None,
) -> None:
    """Create the Pending share (an expired one for the same email is
    replaced by a fresh one)."""
    await conn.execute(
        "INSERT INTO pending_share (base_id, email, created_at, expires_at, created_by)"
        " VALUES (%s, %s, %s, %s, %s)"
        " ON CONFLICT (base_id, email) DO UPDATE SET"
        "   created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at,"
        "   created_by = EXCLUDED.created_by",
        (base_id, email, now, expires_at, by),
    )


async def delete_pending(conn: Connection, base_id: str, pending_id: int) -> str | None:
    """Remove a Pending share; its email, or ``None`` if there was none."""
    cur = await conn.execute(
        "DELETE FROM pending_share WHERE base_id = %s AND id = %s RETURNING email",
        (base_id, pending_id),
    )
    row = await cur.fetchone()
    return str(row["email"]) if row else None


async def count(conn: Connection, base_id: str, now: datetime) -> tuple[int, int]:
    """(Shared users, live Pending shares) on the base."""
    cur = await conn.execute(
        "SELECT (SELECT count(*) FROM share WHERE base_id = %(base)s) AS shares,"
        " (SELECT count(*) FROM pending_share"
        "   WHERE base_id = %(base)s AND expires_at > %(now)s) AS pending",
        {"base": base_id, "now": now},
    )
    row = await cur.fetchone()
    assert row is not None
    return int(row["shares"]), int(row["pending"])


async def pending_for(
    conn: Connection, email: str, now: datetime
) -> list[tuple[int, str, int | None]]:
    """The live Pending shares for ``email``: ``(id, base_id, created_by)``.
    Expired ones for that email are deleted on the way."""
    await conn.execute(
        "DELETE FROM pending_share WHERE email = %s AND expires_at <= %s",
        (email, now),
    )
    cur = await conn.execute(
        "SELECT id, base_id, created_by FROM pending_share"
        " WHERE email = %s ORDER BY id",
        (email,),
    )
    return [
        (int(r["id"]), str(r["base_id"]), r["created_by"]) for r in await cur.fetchall()
    ]
