"""Plain-SQL migrations, applied in filename order at startup.

Add a migration by dropping ``NNNN_short_name.sql`` into ``migrations/``.
Never edit one that has shipped. Each file runs in its own transaction and is
recorded in ``schema_migration``; an advisory lock keeps two starts from
racing (the Deployment is ``Recreate``, but be safe anyway).
"""

from __future__ import annotations

from importlib import resources
from typing import Any

from psycopg import AsyncConnection
from psycopg.rows import tuple_row

_LOCK_ID = 0x5052544C  # arbitrary, constant


def migration_files() -> list[tuple[str, str]]:
    files = resources.files("sp_rtk_portal.db") / "migrations"
    return sorted(
        (f.name.removesuffix(".sql"), f.read_text())
        for f in files.iterdir()
        if f.name.endswith(".sql")
    )


async def apply_migrations(conn: AsyncConnection[Any]) -> list[str]:
    """Apply pending migrations; return the versions applied."""
    applied: list[str] = []
    async with conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_ID,))
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migration ("
            " version text PRIMARY KEY,"
            " applied_at timestamptz NOT NULL DEFAULT now())"
        )
        cur = conn.cursor(row_factory=tuple_row)
        await cur.execute("SELECT version FROM schema_migration")
        done = {row[0] for row in await cur.fetchall()}
        for version, sql in migration_files():
            if version in done:
                continue
            await conn.execute(sql)  # type: ignore[arg-type]
            await conn.execute(
                "INSERT INTO schema_migration (version) VALUES (%s)", (version,)
            )
            applied.append(version)
    return applied
