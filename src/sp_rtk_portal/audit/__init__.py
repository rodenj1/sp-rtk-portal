"""Audit log: who did what, when and from where. Kept 90 days (spec).

Write an entry inside the same transaction as the change it records:
``await audit.record(conn, at=now, kind="login", account_id=..., ip=...)``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg.types.json import Jsonb

from sp_rtk_portal.db import Connection

LOGIN = "login"
PASSWORD_CHANGE = "password_change"
PASSWORD_RECOVERY = "password_recovery"
TOTP_ENABLED = "totp_enabled"
TOTP_DISABLED = "totp_disabled"


async def record(
    conn: Connection,
    *,
    at: datetime,
    kind: str,
    account_id: int | None = None,
    base_id: str | None = None,
    ip: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    await conn.execute(
        "INSERT INTO audit_entry (at, kind, account_id, base_id, ip, detail)"
        " VALUES (%s, %s, %s, %s, %s, %s)",
        (at, kind, account_id, base_id, ip, Jsonb(detail or {})),
    )
