"""A throwaway Postgres server for the test session, plus a fresh database per test.

Where the server comes from, in order:

1. ``PORTAL_TEST_DATABASE_URL``: an existing server you control (superuser URL).
2. Docker, through testcontainers, when a Docker daemon is reachable (CI).
3. ``pgserver``: real Postgres binaries shipped as a wheel, run from a temp dir.
   Lets the suite run on a machine with neither Docker nor Postgres installed.

Each test gets its own database cloned from a migrated template, so tests never
see each other's rows and nobody pays for migrations more than once.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit, urlunsplit

import psycopg

from sp_rtk_portal.db.migrate import apply_migrations

TEMPLATE_DB = "portal_template"


def with_database(url: str, dbname: str) -> str:
    """Return ``url`` pointing at ``dbname`` instead of its own database."""
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=f"/{dbname}"))


@contextmanager
def postgres_server() -> Iterator[str]:
    """Yield a superuser URL for a Postgres server that lives for the session."""
    if url := os.environ.get("PORTAL_TEST_DATABASE_URL"):
        yield url
    elif _docker_available():
        from testcontainers.community.postgres import PostgresContainer

        with PostgresContainer("postgres:16-alpine", driver=None) as pg:
            yield pg.get_connection_url()
    else:
        import pgserver

        with tempfile.TemporaryDirectory(prefix="portal-pg-") as pgdata:
            server = pgserver.get_server(pgdata, cleanup_mode="stop")
            try:
                yield server.get_uri()
            finally:
                server.cleanup()


def _docker_available() -> bool:
    if os.environ.get("PORTAL_TEST_NO_DOCKER"):
        return False
    return shutil.which("docker") is not None or os.path.exists("/var/run/docker.sock")


def create_template(admin_url: str) -> None:
    """(Re)create the migrated template database every test database copies."""
    _drop_and_create(admin_url, TEMPLATE_DB)
    asyncio.run(_migrate(with_database(admin_url, TEMPLATE_DB)))


async def _migrate(url: str) -> None:
    async with await psycopg.AsyncConnection.connect(url) as conn:
        await apply_migrations(conn)


@contextmanager
def fresh_database(admin_url: str) -> Iterator[str]:
    """Yield the URL of a new database cloned from the template; drop it after."""
    name = f"portal_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}" TEMPLATE "{TEMPLATE_DB}"')
    try:
        yield with_database(admin_url, name)
    finally:
        with psycopg.connect(admin_url, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def _drop_and_create(admin_url: str, name: str) -> None:
    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{name}"')
