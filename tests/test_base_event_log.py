"""Seam 1: the base keeps its own record of Remote sessions (ticket #203,
ADR 0005).

The real agent runs on virtual time with the real sp-rtk-base as the base's
UI, reading the agent's control socket as on a base. Each Wake, each Remote
session start (who, and whether Operator or Shared user) and each end (who,
and why) shows up in the base's Event log, read through the base's own
events API: a record on the base, which the Portal can't change.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from sp_rtk_portal_protocol import PROTOCOL_VERSION

from .harness.agent import RunningAgent, running_agent
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser, Portal
from .harness.real_base import RealBase, reading_agent
from .harness.server import serving
from .harness.session_bar import status_channel

OPERATOR = "operator@example.com"
COLLEAGUE = "sam@example.com"
PASSWORD = "correct horse battery staple"

PORTAL_ENTRIES = (
    "portal.wake",
    "portal.remote_session_started",
    "portal.remote_session_ended",
    "portal.tunnel_opened",
    "portal.tunnel_closed",
)


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(OPERATOR, PASSWORD)
    assert (await browser.sign_in(OPERATOR, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
async def server(portal: Portal) -> AsyncIterator[int]:
    async with serving(portal.app) as port:
        yield port


@pytest.fixture
def agent_version() -> int:
    """The protocol version the agent speaks (a test may ask for 1: a
    polling base, reached through Wakes)."""
    return PROTOCOL_VERSION


@pytest.fixture
async def base(
    portal: Portal, server: int, agent_version: int
) -> AsyncIterator[tuple[RunningAgent, RealBase]]:
    """The agent and the real base whose UI its tunnel reaches."""
    async with (
        running_agent(
            portal, server_port=server, protocol_version=agent_version
        ) as agent,
        reading_agent(agent) as ui,
    ):
        yield agent, ui


@pytest.fixture
async def claimed(
    base: tuple[RunningAgent, RealBase], operator: Browser
) -> tuple[RunningAgent, RealBase, str]:
    agent, ui = base
    status = await agent.claim(operator)
    assert status.base_id
    return agent, ui, status.base_id


async def event_log(ui: RealBase) -> list[dict[str, Any]]:
    """The base's Portal entries, oldest first, as its events API lists them."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{ui.url}/api/events", params={"count": 200})
    resp.raise_for_status()
    entries = [e for e in resp.json()["events"] if e["event_type"] in PORTAL_ENTRIES]
    return sorted(entries, key=lambda e: e["timestamp"])


async def until_logged(ui: RealBase, count: int, kind: str) -> list[dict[str, Any]]:
    """Wait (real time: the app reads the agent every 2 s) until the Event
    log holds ``count`` entries of ``kind``; returns them."""
    for _ in range(100):
        found = [e for e in await event_log(ui) if e["event_type"] == kind]
        if len(found) >= count:
            return found
        await asyncio.sleep(0.1)
    raise AssertionError(f"never {count} x {kind}: {await event_log(ui)}")


def summary(entry: dict[str, Any]) -> tuple[str, ...]:
    p = entry["payload"]
    return tuple(
        str(v)
        for v in (entry["event_type"], p.get("who"), p.get("role"), p.get("reason"))
        if v
    )


async def open_remotely(who: Browser, base_id: str) -> None:
    resp = await who.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}, resp.text


async def settle() -> None:
    """Let the Portal's sweeper (real time, against the fake clock) act."""
    await asyncio.sleep(0.1)


@pytest.mark.parametrize("agent_version", [1])  # only a polling base is Woken
async def test_a_wake_and_an_operators_remote_session_are_in_the_bases_event_log(
    portal: Portal,
    operator: Browser,
    claimed: tuple[RunningAgent, RealBase, str],
    server: int,
):
    agent, ui, base_id = claimed
    woken_at = portal.clock.now()

    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)  # the poll that carries the Wake
        await bar.until("connected")
        await agent.run(seconds=20)  # the next poll lists the session
        [wake] = await until_logged(ui, 1, "portal.wake")  # one, however many polls
        [started] = await until_logged(ui, 1, "portal.remote_session_started")
    # Nobody has the Session bar open: idle after 2 min.
    await agent.run(minutes=2)
    await settle()
    await agent.run(seconds=20)
    [ended] = await until_logged(ui, 1, "portal.remote_session_ended")
    await until_logged(ui, 1, "portal.tunnel_closed")

    assert wake["timestamp"] == pytest.approx(woken_at.timestamp() + 20)
    assert wake["payload"] == {}
    assert summary(started) == ("portal.remote_session_started", OPERATOR, "operator")
    assert started["timestamp"] == pytest.approx(woken_at.timestamp())
    assert OPERATOR in started["message"] and "Operator" in started["message"]
    assert summary(ended) == (
        "portal.remote_session_ended",
        OPERATOR,
        "operator",
        "idle",
    )
    assert OPERATOR in ended["message"] and "idle" in ended["message"].lower()
    # The tunnel's own entries stay: it opened on the Wake, and closed.
    kinds = [e["event_type"] for e in await event_log(ui)]
    assert kinds[:3] == [
        "portal.remote_session_started",
        "portal.wake",
        "portal.tunnel_opened",
    ]
    assert kinds[-1] == "portal.tunnel_closed"


async def test_shared_users_and_operators_sessions_end_with_their_reasons(
    portal: Portal,
    operator: Browser,
    authentik: FakeAuthentik,
    claimed: tuple[RunningAgent, RealBase, str],
    server: int,
):
    agent, ui, base_id = claimed
    authentik.add_user(COLLEAGUE, PASSWORD)
    async with portal.browser(ip="198.51.100.9") as sam:
        assert (await sam.sign_in(COLLEAGUE, PASSWORD)).json() == {"next": "/"}
        resp = await operator.action(f"/bases/{base_id}/shares", {"email": COLLEAGUE})
        assert resp.status_code == 200, resp.text
        [shared] = await portal.query(
            "SELECT id FROM account WHERE email = %s", COLLEAGUE
        )

        await open_remotely(operator, base_id)
        await open_remotely(sam, base_id)
        await agent.run(seconds=20)  # Wake; the reply lists both
        await until_logged(ui, 2, "portal.remote_session_started")

        # The Operator takes the Share away, then logs out.
        resp = await operator.action(f"/bases/{base_id}/shares/{shared['id']}/remove")
        assert resp.status_code == 200, resp.text
        assert (await operator.action("/logout")).status_code == 200
        await agent.run(seconds=20)
        ends = await until_logged(ui, 2, "portal.remote_session_ended")

    starts = await until_logged(ui, 2, "portal.remote_session_started")
    assert sorted(summary(e) for e in starts) == [
        ("portal.remote_session_started", OPERATOR, "operator"),
        ("portal.remote_session_started", COLLEAGUE, "shared_user"),
    ]
    assert any("Shared user" in e["message"] for e in starts)
    assert sorted(summary(e) for e in ends) == [
        ("portal.remote_session_ended", OPERATOR, "operator", "left"),
        ("portal.remote_session_ended", COLLEAGUE, "shared_user", "revoked"),
    ]


async def test_the_hard_cap_and_a_pause_are_the_recorded_reasons(
    operator: Browser,
    claimed: tuple[RunningAgent, RealBase, str],
    server: int,
):
    agent, ui, base_id = claimed

    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)
        await bar.until("connected")
        # Meanwhile the agent's idle backstop closes the frameless tunnel
        # and the Portal re-Wakes it, every few minutes: older entries leave
        # the Event log (it keeps the latest 50).
        await bar.run(agent, minutes=60)
        await bar.until("ended")
        await agent.run(seconds=20)
        await until_logged(ui, 1, "portal.remote_session_ended")

    await open_remotely(operator, base_id)  # Reconnect: a new Remote session
    await agent.run(seconds=20)
    assert [s.who for s in (await agent.status()).sessions] == [OPERATOR]
    await agent.pause()  # on the base's local page: the Portal ends it
    ends = await until_logged(ui, 2, "portal.remote_session_ended")

    assert [summary(e) for e in ends] == [
        ("portal.remote_session_ended", OPERATOR, "operator", "hard_cap"),
        ("portal.remote_session_ended", OPERATOR, "operator", "paused"),
    ]
