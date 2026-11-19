"""Seam 1: a base holding its tunnel talks to the Portal on it (ticket #205).

A holding agent makes no HTTPS polls or Check-ins. Its Check-ins travel on
the tunnel (on connect, every 5 min and on any change) and the Portal
records them as it does an HTTPS Check-in, public IP included. The agent
config, notices and Remote sessions come back on the tunnel, on connect and
within a second of a change, and the base's local Portal page shows them.
Every ping advances the base's last-seen.

The Portal is served over real TCP (websockets); the agent runs on virtual
time.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timedelta

import pytest
from sp_rtk_base import __version__ as base_version
from sp_rtk_portal_protocol import (
    CLAIM_TOKEN_PATH,
    CLAIMS_PATH,
    CheckIn,
    Message,
    read_control,
)
from sp_rtk_portal_protocol.tunnel import Kind

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.fake_authentik import FakeAuthentik
from .harness.pages import base_card
from .harness.portal import PORTAL_OWNER, Browser, Portal
from .harness.server import serving
from .test_held_tunnel import eventually, held

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
async def owner(portal: Portal, authentik: FakeAuthentik) -> AsyncIterator[Browser]:
    """The Portal owner, signed in."""
    authentik.add_user(PORTAL_OWNER, PASSWORD)
    async with portal.browser() as b:
        assert (await b.sign_in(PORTAL_OWNER, PASSWORD)).json() == {"next": "/"}
        yield b


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


def https_paths(agent: RunningAgent) -> list[str]:
    """What the agent asked the Portal over HTTPS, beyond its Claim."""
    return [
        r.path for r in agent.requests if r.path not in (CLAIMS_PATH, CLAIM_TOKEN_PATH)
    ]


def control(agent: RunningAgent, *, sent: bool) -> list[tuple[timedelta, Message]]:
    """The control messages the agent sent (or received) on its tunnel, and
    when, from the first frame of either kind."""
    frames = [f for f in agent.frames if f.kind == Kind.CONTROL]
    start = frames[0].at if frames else None
    found: list[tuple[timedelta, Message]] = []
    for f in frames:
        message = read_control(f.payload)
        if f.sent == sent and message is not None and start is not None:
            found.append((f.at - start, message))
    return found


def check_ins(agent: RunningAgent) -> list[tuple[timedelta, CheckIn]]:
    return [(at, m) for at, m in control(agent, sent=True) if isinstance(m, CheckIn)]


async def card(operator: Browser, agent: RunningAgent) -> dict[str, list[str]]:
    base_id = (await agent.status()).base_id
    assert base_id
    return base_card((await operator.get("/")).text, base_id)


async def within_a_second(check: Callable[[], Awaitable[bool]], what: str) -> None:
    """``check`` comes true within a second of real time (no virtual time
    passes: no poll could have carried it)."""
    deadline = asyncio.get_running_loop().time() + 1
    while not await check():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(f"not within a second: {what}")
        await asyncio.sleep(0.01)


# --- Check-ins -------------------------------------------------------------------


async def test_a_holding_agent_sends_no_https_polls_or_check_ins_for_hours(
    portal: Portal, agent: RunningAgent
):
    await held(portal, agent)

    await agent.run(hours=3)

    assert https_paths(agent) == []
    assert (await agent.status()).connection_mode == "holding"


async def test_the_check_in_on_connect_shows_on_the_base_with_its_public_ip(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    await held(portal, agent)

    [(_, first)] = check_ins(agent)
    assert first.mode == "holding"

    async def recorded() -> bool:
        return "lan" in await card(operator, agent)

    await eventually(recorded, "the Portal records the Check-in")
    found = await card(operator, agent)
    assert found["version"] == [f"sp-rtk-base {base_version}"]
    assert found["lan"] == ["192.168.1.20 (eth0, primary)", "10.8.0.4 (wlan0)"]
    assert found["public-ip"] == [agent.ip]
    assert found["connection"] == ["Holding its tunnel"]
    assert https_paths(agent) == []


async def test_a_check_in_comes_every_5_min_and_on_a_lan_address_change(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    await held(portal, agent)

    await agent.run(minutes=15)
    assert [at for at, _ in check_ins(agent)] == [
        timedelta(minutes=m) for m in (0, 5, 10, 15)
    ]

    agent.lan = []  # the base's LAN address goes away
    await agent.run(seconds=20)
    [*_, (at, latest)] = check_ins(agent)
    assert at > timedelta(minutes=15)
    assert latest.lan_addresses == []

    async def recorded() -> bool:
        return "lan" not in await card(operator, agent)

    await eventually(recorded, "the Portal records the Check-in")
    assert https_paths(agent) == []


async def test_a_new_tunnel_from_a_new_public_ip_checks_in_from_it(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    await held(portal, agent)

    agent.ip = "198.51.100.99"  # the base moved; its agent restarts
    await agent.restart()
    await held(portal, agent)

    assert len(check_ins(agent)) == 2

    async def recorded() -> bool:
        return (await card(operator, agent))["public-ip"] == ["198.51.100.99"]

    await eventually(recorded, "the Portal records the new public IP")
    assert https_paths(agent) == []


# --- Last-seen -------------------------------------------------------------------


async def test_last_seen_advances_with_each_ping(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    await held(portal, agent)
    opened = portal.clock.now()

    for ping in range(1, 6):
        await agent.run(seconds=50)

        async def seen() -> bool:
            found = await card(operator, agent)
            at = datetime.fromisoformat(found["last-seen@datetime"][0])
            return at == opened + timedelta(seconds=50 * ping)  # noqa: B023

        await eventually(seen, f"last-seen at ping {ping}")


# --- Config, notices and Remote sessions -------------------------------------------


async def test_a_config_change_reaches_the_agent_on_its_tunnel_within_a_second(
    portal: Portal, agent: RunningAgent, owner: Browser
):
    await held(portal, agent)
    before = (await agent.status()).config_revision
    assert before is not None

    resp = await owner.action("/settings/agent-config", {"check_in_interval": 600})
    assert resp.status_code == 200, resp.text

    async def applied() -> bool:
        return (await agent.status()).config_revision == before + 1

    await within_a_second(applied, "the new config revision on the local page")
    # The agent goes by it: its next Check-in is 10 min after the last.
    await agent.run(minutes=20)
    assert [at for at, _ in check_ins(agent)] == [
        timedelta(minutes=m) for m in (0, 5, 15)
    ]
    assert https_paths(agent) == []


async def test_a_notice_and_metered_reach_the_agent_on_its_tunnel_within_a_second(
    portal: Portal, agent: RunningAgent, owner: Browser, operator: Browser
):
    base_id = await held(portal, agent)

    resp = await owner.action("/settings/notices", {"text": "Portal moves soon"})
    assert resp.status_code == 200, resp.text

    async def noticed() -> bool:
        return (await agent.status()).notices == ["Portal moves soon"]

    await within_a_second(noticed, "the notice on the local page")

    resp = await operator.action(f"/bases/{base_id}/metered", {"metered": "true"})
    assert resp.status_code == 200, resp.text

    async def metered() -> bool:
        return (await agent.status()).metered is True

    await within_a_second(metered, "metered on the local page")
    assert https_paths(agent) == []


async def test_a_remote_session_and_its_end_reach_the_agent_within_a_second(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    base_id = await held(portal, agent)

    resp = await operator.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}, resp.text

    async def live() -> bool:
        return [s.who for s in (await agent.status()).sessions] == [EMAIL]

    await within_a_second(live, "the Remote session on the local page")

    assert (await operator.action("/logout")).status_code == 200

    async def ended() -> bool:
        status = await agent.status()
        return not status.sessions and any(
            e.event == "session_ended" for e in status.remote_events
        )

    await within_a_second(ended, "the end in the base's record")
    [started, end] = (await agent.status()).remote_events
    assert (started.event, started.who) == ("session_started", EMAIL)
    assert (end.event, end.who, end.reason) == ("session_ended", EMAIL, "left")
    assert https_paths(agent) == []
