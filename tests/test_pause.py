"""Seam 1: remote access paused on site (ticket #92).

The Operator pauses remote access on the base's local Portal page. The real
agent keeps its Claim and keeps polling, reports ``paused`` and ignores
Wakes; the Portal shows "Remote access paused", refuses Open remotely and
ends the base's live Remote sessions. Only the base can resume. The agent
also learns from each poll who is using the base remotely.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
from sp_rtk_portal_protocol import CHECK_IN_PATH, CheckIn

from .harness.agent import BASE_IP, RunningAgent, running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.fake_authentik import FakeAuthentik
from .harness.pages import base_card, entries, fields
from .harness.portal import Browser, Portal
from .harness.server import serving
from .harness.session_bar import status_channel
from .harness.signer import signing_agent

EMAIL = "operator@example.com"
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


async def base_of(agent: RunningAgent) -> str:
    base_id = (await agent.status()).base_id
    assert base_id
    return base_id


async def eventually(check: Callable[[], Awaitable[bool] | bool], what: str) -> None:
    for _ in range(500):
        result = check()
        if isinstance(result, Awaitable):
            result = await result
        if result:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"never: {what}")


async def card(browser: Browser, base_id: str) -> tuple[str, dict[str, list[str]]]:
    """The base's ``data-state`` in the list, and its fields."""
    f = base_card((await browser.get("/")).text, base_id)
    return f["@data-state"][0], f


async def test_a_paused_base_shows_remote_access_paused_and_cannot_be_opened(
    operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)

    status = await agent.pause()

    assert status.state == "paused"
    state, f = await card(operator, base_id)
    assert state == "paused"
    assert f["state"] == ["Remote access paused"]
    assert "open-remotely@disabled" in f
    resp = await operator.action(f"/bases/{base_id}/remote")
    assert resp.status_code == 409
    assert "paused" in resp.json()["error"]

    await agent.run(minutes=5)  # still polling: paused, not offline
    assert (await card(operator, base_id))[0] == "paused"

    await agent.resume()

    state, f = await card(operator, base_id)
    assert (state, f["state"]) == ("online", ["Online"])
    assert "open-remotely@disabled" not in f


async def test_a_check_in_carries_the_pause_for_a_base_that_rarely_polls(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    """In Doorbell mode the agent polls only while its tunnel is open, so
    its Check-ins say whether remote access is paused too."""
    base_id = await base_of(agent)

    async with signing_agent(portal, ip=BASE_IP) as base:

        async def check_in(**fields: object) -> None:
            portal.clock.advance(minutes=5)  # one Check-in interval later
            body = CheckIn(software_version="0.11.0").to_json()
            body.pop("paused")
            resp = await base.post(CHECK_IN_PATH, body | fields, key=agent.key)
            assert resp.status_code == 200, resp.text

        await check_in(paused=True)
        state, f = await card(operator, base_id)
        assert (state, f["state"]) == ("paused", ["Remote access paused"])
        whats = [e["what"] for e in entries((await operator.get("/audit")).text)]
        assert "Remote access paused on the base" in whats

        await check_in()  # an agent from before the field: no change
        assert (await card(operator, base_id))[0] == "paused"

        await check_in(paused=False)
        assert (await card(operator, base_id))[0] == "online"


async def test_a_paused_agent_opens_no_tunnel_for_a_wake_sent_anyway(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    await agent.pause()

    portal.context.tunnels.wake(base_id)  # as a misbehaving Portal might
    await agent.run(minutes=1)

    assert agent.tunnel_urls == []
    assert (await agent.status()).tunnel == "closed"

    await agent.resume()
    resp = await operator.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}
    await agent.run(seconds=20)
    await eventually(
        lambda: portal.context.tunnels.tunnel_up(base_id), "the tunnel opened"
    )


async def test_pausing_cuts_live_remote_sessions_and_revokes_their_tokens(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    tunnels = portal.context.tunnels
    [account] = await portal.query("SELECT id FROM account WHERE email = %s", EMAIL)
    await operator.action(f"/bases/{base_id}/remote")
    session = tunnels.session_for(account["id"], base_id)
    assert session is not None

    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)
        await bar.until("connected")

        await agent.pause()

        ended = await bar.until("ended")

    assert ended["reason"] == "paused"
    page = fields((await operator.get(f"/bases/{base_id}")).text)
    assert page["status"] == ["Remote access paused"]
    assert "remote-paused" in page
    assert tunnels.lookup(base_id, session.token) is None
    assert not tunnels.tunnel_up(base_id)
    assert (await agent.status()).tunnel == "closed"
    entries = await portal.query(
        "SELECT kind, base_id, detail FROM audit_entry"
        " WHERE kind IN ('remote_session_end', 'remote_access_paused',"
        " 'remote_access_resumed') ORDER BY id"
    )
    assert [(e["kind"], e["base_id"]) for e in entries] == [
        ("remote_access_paused", base_id),
        ("remote_session_end", base_id),
    ]
    assert entries[1]["detail"]["reason"] == "paused"

    await agent.resume()
    entries = await portal.query(
        "SELECT kind FROM audit_entry WHERE kind = 'remote_access_resumed'"
    )
    assert len(entries) == 1


async def test_the_agent_learns_who_is_connected_remotely_and_since_when(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    started = portal.clock.now()

    await operator.action(f"/bases/{base_id}/remote")
    await agent.run(seconds=20)

    [session] = (await agent.status()).sessions
    assert (session.who, session.since, session.shared) == (EMAIL, started, False)
