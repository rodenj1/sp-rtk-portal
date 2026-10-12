"""Seam-1 fixtures.

- ``portal``: the real app, running (lifespan entered) against this test's own
  database. ``portal.browser(ip=...)`` opens another browser; ``portal.query``
  reads the database directly.
- ``browser``: one browser on the Portal, keeping cookies. ``browser.action``
  sends a state-changing request the way the Portal's pages do;
  ``browser.sign_in`` runs the login steps; ``browser.http`` is the raw client.
- ``authentik``: the fake Authentik (``add_user``, ``script_challenge``, ...).
- ``clock``: the fake clock the Portal reads (``clock.advance(days=30)``).
- ``database_url``: a fresh database cloned from the migrated template.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import pytest

from .harness.clock import FakeClock
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser, Portal, running_portal
from .harness.postgres import create_template, fresh_database, postgres_server


@pytest.fixture(scope="session")
def postgres_admin_url() -> Iterator[str]:
    with postgres_server() as url:
        create_template(url)
        yield url


@pytest.fixture
def database_url(postgres_admin_url: str) -> Iterator[str]:
    with fresh_database(postgres_admin_url) as url:
        yield url


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def authentik(clock: FakeClock) -> FakeAuthentik:
    return FakeAuthentik(clock)


@pytest.fixture
async def portal(
    database_url: str, clock: FakeClock, authentik: FakeAuthentik
) -> AsyncIterator[Portal]:
    async with running_portal(database_url, clock, authentik) as p:
        yield p


@pytest.fixture
async def browser(portal: Portal) -> AsyncIterator[Browser]:
    async with portal.browser() as b:
        yield b
