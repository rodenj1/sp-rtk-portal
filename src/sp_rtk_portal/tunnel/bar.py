"""What the Session bar shows: one status message per change, sent over its
status channel (``/bases/<id>/session``).

``{"state": "waking" | "reconnecting" | "didnt_wake" | "connected" | "ended",
"reason": <why it ended> | None, "frame": "/b/<id>/s/<token>/" (until it
ends), "still_there": bool, "cap_at": ISO time the hard cap pauses it,
"present": [{"name", "role"}] (other users with a Session bar open on this
base), "last_seen": "YYYY-MM-DD HH:MM UTC" | "never", "wake_mode": "Doorbell"
| "Polling every 20 s" ...}``.

An ended session with reason ``hard_cap`` is shown as Session paused.
"""

from __future__ import annotations

from typing import Any

from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.bases import online, store
from sp_rtk_portal.context import PortalContext
from sp_rtk_portal.db import Connection
from sp_rtk_portal.proxy.middleware import frame_path
from sp_rtk_portal.tunnel.broker import RemoteSession
from sp_rtk_portal.web.templates import utc

OPERATOR = "Operator"
SHARED_USER = "Shared user"


def last_seen(base: store.BaseSummary) -> str:
    return f"{utc(base.last_seen_at)} UTC" if base.last_seen_at else "never"


async def status(ctx: PortalContext, session: RemoteSession) -> dict[str, Any]:
    broker = ctx.tunnels
    async with ctx.db.connection() as conn:
        base = await store.by_id(conn, session.base_id)
        config = await agent_config.current(conn, ctx.settings)
        others = [
            s.account_id
            for s in broker.present(session.base_id)
            if s.account_id != session.account_id
        ]
        present = await _names(conn, session.base_id, others)
    message: dict[str, Any] = {
        "state": broker.state(session),
        "reason": session.end_reason,
        "still_there": broker.still_there(session),
        "cap_at": broker.cap_at(session).isoformat(),
        "present": present,
    }
    if not session.ended:
        message["frame"] = frame_path(session)
    if base is not None:
        message["last_seen"] = last_seen(base)
        message["wake_mode"] = online.wake_mode(base, config)
    return message


async def _names(
    conn: Connection, base_id: str, account_ids: list[int]
) -> list[dict[str, str]]:
    if not account_ids:
        return []
    cur = await conn.execute(
        "SELECT a.email, a.id = b.owner_account_id AS operator"
        " FROM account a JOIN base b ON b.id = %s"
        " WHERE a.id = ANY(%s) ORDER BY lower(a.email)",
        (base_id, account_ids),
    )
    return [
        {"name": row["email"], "role": OPERATOR if row["operator"] else SHARED_USER}
        for row in await cur.fetchall()
    ]
