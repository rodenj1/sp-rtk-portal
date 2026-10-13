"""Seam 1: the Session bar's states as its status channel reports them
(ticket #90): Waking, Didn't wake, Offline, Reconnecting, Still there?,
Session paused, and who else is connected.

The Portal is served over real TCP; the real agent runs on virtual time and
the Portal's clock is fake, so every timeout is reached by letting exactly
that much time pass.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser, Portal
from .harness.server import serving
from .harness.session_bar import status_channel
from .test_tunnel import base_of, eventually, open_remotely, wait_tunnel

EMAIL = "operator@example.com"
OTHER = "sam@example.com"
PASSWORD = "correct horse battery staple"


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
async def server(portal: Portal) -> AsyncIterator[int]:
    async with serving(portal.app) as port:
        yield port


@pytest.fixture
async def ui() -> AsyncIterator[BaseUi]:
    async with base_ui() as stub:
        yield stub


@pytest.fixture
async def agent(
    portal: Portal, operator: Browser, server: int, ui: BaseUi
) -> AsyncIterator[RunningAgent]:
    async with running_agent(portal, server_port=server, app_port=ui.port) as a:
        await a.claim(operator)
        yield a


@pytest.fixture
async def colleague(portal: Portal, authentik: FakeAuthentik) -> AsyncIterator[Browser]:
    authentik.add_user(OTHER, PASSWORD)
    async with portal.browser(ip="203.0.113.99") as b:
        assert (await b.sign_in(OTHER, PASSWORD)).json() == {"next": "/"}
        yield b


async def settle() -> None:
    """Give the sweeper (every 10 ms in tests) a chance to notice the time."""
    await asyncio.sleep(0.1)


# --- Waking and Didn't wake -----------------------------------------------------


async def test_a_base_that_doesnt_answer_the_wake_shows_didnt_wake_after_poll_interval_plus_15_s(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    agent.reachable = False  # online a moment ago, but its polls stop arriving

    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        assert (await bar.until("waking"))["state"] == "waking"
        await agent.run(seconds=34)
        await settle()
        assert bar.state == "waking"
        await agent.run(seconds=1)
        didnt = await bar.until("didnt_wake")

    assert didnt["wake_mode"] == "Polling every 20 s"
    assert didnt["last_seen"] == "2026-01-01 12:00 UTC"


async def test_a_metered_base_gets_75_s_before_didnt_wake(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    resp = await operator.action(f"/bases/{base_id}/metered", {"metered": "true"})
    assert resp.json() == {"next": "/"}
    agent.reachable = False

    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await bar.until("waking")
        await agent.run(seconds=74)
        await settle()
        assert bar.state == "waking"
        await agent.run(seconds=1)
        didnt = await bar.until("didnt_wake")

    assert didnt["wake_mode"] == "Polling every 60 s (metered)"


# --- Offline -----------------------------------------------------------------------


async def test_an_offline_base_is_not_woken_and_says_offline_until_try_anyway(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    agent.reachable = False
    await agent.run(seconds=61)  # 3 missed beats: offline
    agent.reachable = True

    await open_remotely(operator, base_id)
    page = await operator.get(f"/bases/{base_id}")

    assert 'data-state="offline"' in page.text
    assert "offline, last seen 2026-01-01 12:00 UTC" in page.text
    assert "Try anyway" in page.text
    await agent.run(seconds=40)  # it polls again, and is told nothing
    assert (await agent.status()).tunnel == "closed"
    assert not portal.context.tunnels.tunnel_up(base_id)

    resp = await operator.action(f"/bases/{base_id}/remote", {"try_anyway": "1"})
    assert resp.json() == {"next": f"/bases/{base_id}"}
    async with status_channel(server, operator, base_id) as bar:
        await bar.until("waking")
        await agent.run(seconds=20)
        await bar.until("connected")


# --- Reconnecting ------------------------------------------------------------------


async def test_a_dropped_tunnel_shows_reconnecting_and_the_portal_wakes_the_base_once_more(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)
        before = await bar.until("connected")

        agent.drop_tunnel()
        await bar.until("reconnecting")
        await wait_tunnel(agent, "closed")
        await agent.run(seconds=20)  # its next poll carries the new Wake
        after = await bar.until("connected")

    assert after["frame"] == before["frame"]  # same token: no new login
    resp = await operator.get(after["frame"])
    assert resp.status_code == 200


async def test_when_the_reconnect_wake_goes_unanswered_the_bar_shows_didnt_wake(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)
        await bar.until("connected")

        agent.reachable = False
        agent.drop_tunnel()
        await bar.until("reconnecting")
        await agent.run(seconds=36)
        await bar.until("didnt_wake")

        # Retry Wakes it again.
        agent.reachable = True
        await open_remotely(operator, base_id)
        await bar.until("waking")
        await agent.run(seconds=20)
        await bar.until("connected")


# --- Still there? and Session paused ----------------------------------------------


async def test_still_there_at_55_min_and_keep_going_restarts_the_60_min(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)
        assert (await bar.until("connected"))["still_there"] is False
        await agent.run(minutes=54, seconds=39)
        await settle()
        assert bar.messages[-1]["still_there"] is False
        await agent.run(seconds=1)  # 55 min after Open remotely
        await eventually(lambda: bar.messages[-1]["still_there"], "Still there?")

        resp = await operator.action(f"/bases/{base_id}/keep-going")
        assert resp.status_code == 200, resp.text
        await eventually(lambda: not bar.messages[-1]["still_there"], "kept going")

        await agent.run(minutes=54)  # 109 min in: well past the first hour
        await settle()
        assert bar.state == "connected"
        assert bar.messages[-1]["still_there"] is False
        await agent.run(minutes=1)
        await eventually(lambda: bar.messages[-1]["still_there"], "asked again")


async def test_without_keep_going_the_session_pauses_at_60_min_and_reconnect_mints_a_new_token(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)
        old = (await bar.until("connected"))["frame"]
        await agent.run(minutes=59, seconds=40)
        paused = await bar.until("ended")
    assert paused["reason"] == "hard_cap"
    assert "frame" not in paused
    assert (await operator.get(old)).status_code == 403

    await open_remotely(operator, base_id)  # Reconnect
    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)
        new = (await bar.until("connected"))["frame"]
    assert new != old
    assert (await operator.get(new)).status_code == 200
    assert (await operator.get(old)).status_code == 403


async def test_keep_going_needs_a_remote_session(
    operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    resp = await operator.action(f"/bases/{base_id}/keep-going")
    assert resp.status_code == 404


# --- Presence --------------------------------------------------------------------


async def test_presence_lists_the_other_connected_users_and_updates_when_they_leave(
    portal: Portal,
    operator: Browser,
    colleague: Browser,
    agent: RunningAgent,
    server: int,
):
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as mine:
        await agent.run(seconds=20)
        assert (await mine.until("connected"))["present"] == []
        shared = await operator.action(f"/bases/{base_id}/shares", {"email": OTHER})
        assert shared.status_code == 200, shared.text
        await open_remotely(colleague, base_id)
        async with status_channel(server, colleague, base_id) as theirs:
            await eventually(
                lambda: (
                    mine.messages[-1]["present"]
                    == [{"name": OTHER, "role": "Shared user"}]
                ),
                "Sam shows as connected",
            )
            await theirs.until("connected")
            assert theirs.messages[-1]["present"] == [
                {"name": EMAIL, "role": "Operator"}
            ]
        await eventually(lambda: mine.messages[-1]["present"] == [], "Sam left")


async def test_offline_and_didnt_wake_offer_open_locally_at_the_lan_address(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    agent.reachable = False

    await open_remotely(operator, base_id)
    await agent.run(seconds=35)  # Didn't wake
    page = (await operator.get(f"/bases/{base_id}")).text
    assert 'data-state="didnt_wake"' in page
    assert 'href="http://192.168.1.20:8080/"' in page
    assert "Open locally (192.168.1.20)" in page
