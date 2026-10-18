"""Portal sessions: a ``__Host-`` cookie holding a random token.

The cookie is ``HttpOnly; Secure; SameSite=Lax; Path=/``, lasts 30 days and
renews on use. The database keeps only a hash of the token, so a database
leak doesn't hand out sessions.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

from starlette.responses import Response

from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.db import Connection

COOKIE = "__Host-portal_session"


def token_hash(token: str) -> bytes:
    """What the database keeps of a session token."""
    return hashlib.sha256(token.encode()).digest()


async def start(
    conn: Connection, account_id: int, now: datetime, lifetime: timedelta
) -> str:
    token = secrets.token_urlsafe(32)
    await conn.execute(
        "INSERT INTO portal_session (token_hash, account_id, created_at,"
        " last_used_at, expires_at) VALUES (%s, %s, %s, %s, %s)",
        (token_hash(token), account_id, now, now, now + lifetime),
    )
    return token


async def resume(
    conn: Connection, token: str, now: datetime, lifetime: timedelta
) -> Account | None:
    """The session's account if it's live, renewing it; else None."""
    cur = await conn.execute(
        "UPDATE portal_session s SET last_used_at = %s, expires_at = %s"
        " FROM account a"
        " WHERE s.token_hash = %s AND s.expires_at > %s AND a.id = s.account_id"
        " RETURNING a.id, a.email, a.email_verified",
        (now, now + lifetime, token_hash(token), now),
    )
    row = await cur.fetchone()
    return Account(**row) if row else None


async def end(conn: Connection, token: str) -> int | None:
    """End the session behind ``token``; its account's id, or ``None`` if
    there was none."""
    cur = await conn.execute(
        "DELETE FROM portal_session WHERE token_hash = %s RETURNING account_id",
        (token_hash(token),),
    )
    row = await cur.fetchone()
    return None if row is None else int(row["account_id"])


def set_cookie(response: Response, token: str, lifetime: timedelta) -> None:
    response.set_cookie(
        COOKIE,
        token,
        max_age=int(lifetime.total_seconds()),
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="lax")
