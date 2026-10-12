"""Postgres access: one async connection pool for the app.

Modules take a connection with ``async with db.connection() as conn`` and use
plain SQL. A ``connection()`` block is one transaction: it commits on exit and
rolls back on error.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from psycopg import AsyncConnection
from psycopg.rows import DictRow, dict_row
from psycopg_pool import AsyncConnectionPool

from sp_rtk_portal.db.migrate import apply_migrations

Connection = AsyncConnection[DictRow]


class Database:
    def __init__(self, url: str) -> None:
        self._pool: AsyncConnectionPool[Connection] = AsyncConnectionPool(
            url,
            open=False,
            min_size=1,
            max_size=10,
            kwargs={"row_factory": dict_row},
        )

    async def open(self) -> None:
        await self._pool.open(wait=True)
        async with self.connection() as conn:
            await apply_migrations(conn)

    async def close(self) -> None:
        await self._pool.close()

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[Connection]:
        async with self._pool.connection() as conn:
            yield conn

    async def ping(self) -> bool:
        try:
            async with self.connection() as conn:
                await conn.execute("SELECT 1")
        except Exception:
            return False
        return True
