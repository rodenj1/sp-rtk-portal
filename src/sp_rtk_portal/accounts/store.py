"""Portal accounts, keyed on ``(iss, sub)`` with ``sub_mode = user_uuid``.

Email and ``email_verified`` are Authentik's to change, so every login
re-reads them.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sp_rtk_portal.accounts.authentik import Identity
from sp_rtk_portal.db import Connection


@dataclass(frozen=True)
class Account:
    id: int
    email: str
    email_verified: bool


async def upsert_on_login(
    conn: Connection, identity: Identity, now: datetime
) -> Account:
    cur = await conn.execute(
        "INSERT INTO account (iss, sub, email, email_verified, created_at, last_login_at)"
        " VALUES (%s, %s, %s, %s, %s, %s)"
        " ON CONFLICT (iss, sub) DO UPDATE SET"
        "   email = EXCLUDED.email,"
        "   email_verified = EXCLUDED.email_verified,"
        "   last_login_at = EXCLUDED.last_login_at"
        " RETURNING id, email, email_verified",
        (identity.iss, identity.sub, identity.email, identity.email_verified, now, now),
    )
    row = await cur.fetchone()
    assert row is not None
    return Account(**row)


async def authentik_sub(conn: Connection, account_id: int) -> str:
    """The account's Authentik user UUID (``sub``, with ``sub_mode = user_uuid``)."""
    cur = await conn.execute("SELECT sub FROM account WHERE id = %s", (account_id,))
    row = await cur.fetchone()
    assert row is not None
    return str(row["sub"])
