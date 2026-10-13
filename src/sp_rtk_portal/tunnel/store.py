"""Remote session records and their audit entries."""

from __future__ import annotations

import hashlib
from datetime import datetime

from sp_rtk_portal import audit
from sp_rtk_portal.db import Connection


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


async def started(
    conn: Connection,
    *,
    account_id: int,
    base_id: str,
    token: str,
    now: datetime,
    ip: str | None,
) -> int:
    cur = await conn.execute(
        "INSERT INTO remote_session (account_id, base_id, token_hash, started_at,"
        " last_activity_at, ip) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
        (account_id, base_id, token_hash(token), now, now, ip),
    )
    row = await cur.fetchone()
    assert row is not None
    await audit.record(
        conn,
        at=now,
        kind=audit.REMOTE_SESSION_START,
        account_id=account_id,
        base_id=base_id,
        ip=ip,
        detail={"remote_session": row["id"]},
    )
    return int(row["id"])


async def ended(
    conn: Connection,
    *,
    session_id: int,
    account_id: int,
    base_id: str,
    now: datetime,
    last_activity: datetime,
    reason: str,
    ip: str | None,
) -> None:
    await conn.execute(
        "UPDATE remote_session SET ended_at = %s, end_reason = %s,"
        " last_activity_at = %s WHERE id = %s AND ended_at IS NULL",
        (now, reason, last_activity, session_id),
    )
    await audit.record(
        conn,
        at=now,
        kind=audit.REMOTE_SESSION_END,
        account_id=account_id,
        base_id=base_id,
        ip=ip,
        detail={"remote_session": session_id, "reason": reason},
    )


async def end_leftovers(conn: Connection, now: datetime) -> int:
    """End the Remote sessions a previous Portal process left open."""
    cur = await conn.execute(
        "UPDATE remote_session SET ended_at = %s, end_reason = 'portal_restart'"
        " WHERE ended_at IS NULL"
        " RETURNING id, account_id, base_id, host(ip) AS ip",
        (now,),
    )
    rows = await cur.fetchall()
    for row in rows:
        await audit.record(
            conn,
            at=now,
            kind=audit.REMOTE_SESSION_END,
            account_id=row["account_id"],
            base_id=row["base_id"],
            ip=row["ip"],
            detail={"remote_session": row["id"], "reason": "portal_restart"},
        )
    return len(rows)
