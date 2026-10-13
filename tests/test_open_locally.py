"""Seam 1: the base list offers Local access (ticket #97).

Each base with a LAN address gets an "Open locally" link to its own UI at its
primary LAN address on :8080. Which of Open locally and Open remotely comes
first depends on whether the browser's public IP is the base's. Whether the
browser can actually reach the base is checked in the browser (Chromium only,
see ``test_open_locally_browser.py``).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sp_rtk_portal_protocol import LanAddress

from .harness.agent import RunningAgent, running_agent
from .harness.fake_authentik import FakeAuthentik
from .harness.pages import base_card
from .harness.portal import CLIENT_IP, Browser, Portal

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"
OPEN = ("open-locally", "open-remotely")


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
async def agent(portal: Portal, operator: Browser) -> AsyncIterator[RunningAgent]:
    """A Claimed base behind another public IP than the operator's."""
    async with running_agent(portal) as a:
        await a.claim(operator)
        yield a


async def _card(operator: Browser, agent: RunningAgent) -> dict[str, list[str]]:
    base_id = (await agent.status()).base_id
    assert base_id
    page = await operator.get("/")
    assert page.status_code == 200
    return base_card(page.text, base_id)


def _order(card: dict[str, list[str]]) -> list[str]:
    """The Open choices in the order the page shows them."""
    return [field for field in card if field in OPEN]


async def test_behind_the_bases_public_ip_open_locally_comes_first(
    portal: Portal, operator: Browser
):
    async with running_agent(portal, ip=CLIENT_IP) as agent:
        await agent.claim(operator)

        card = await _card(operator, agent)

    assert _order(card) == ["open-locally", "open-remotely"]
    assert card["open-locally"] == ["Open locally (192.168.1.20)"]
    assert card["open-locally@href"] == ["http://192.168.1.20:8080/"]


async def test_elsewhere_open_remotely_comes_first_and_open_locally_shows_the_lan_ip(
    operator: Browser, agent: RunningAgent
):
    card = await _card(operator, agent)

    assert _order(card) == ["open-remotely", "open-locally"]
    assert card["open-locally"] == ["Open locally (192.168.1.20)"]
    assert card["open-locally@href"] == ["http://192.168.1.20:8080/"]


async def test_without_a_lan_address_there_is_no_open_locally(
    operator: Browser, agent: RunningAgent
):
    agent.lan = []
    await agent.run(minutes=5)  # the next Check-in

    card = await _card(operator, agent)

    assert _order(card) == ["open-remotely"]


async def test_only_a_non_global_ip_literal_from_the_base_is_ever_linked(
    operator: Browser, agent: RunningAgent
):
    agent.lan = [
        LanAddress(address="evil.example", interface="eth0", primary=True),
        LanAddress(address="8.8.8.8", interface="eth1", primary=True),
        LanAddress(address="10.8.0.4", interface="wlan0"),
    ]
    await agent.run(minutes=5)

    card = await _card(operator, agent)

    assert card["open-locally@href"] == ["http://10.8.0.4:8080/"]


async def test_the_base_list_may_fetch_each_bases_identity_endpoint_and_nothing_else(
    operator: Browser, agent: RunningAgent
):
    page = await operator.get("/")

    policy = dict(
        d.strip().split(" ", 1)
        for d in page.headers["content-security-policy"].split(";")
    )
    assert policy["connect-src"] == (
        "'self' http://192.168.1.20:8080/api/portal/identity"
    )


async def test_other_pages_keep_the_strict_connect_src(
    operator: Browser, agent: RunningAgent
):
    page = await operator.get("/account")

    assert "connect-src 'self';" in page.headers["content-security-policy"]
