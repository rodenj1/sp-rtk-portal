"""Seam-1 fixtures. Tests use ``portal``, ``browser``, ``authentik`` and ``clock``.

See SCRATCH notes / README "Tests" for what each fixture is for.
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
