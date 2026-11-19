"""Seam 1: leased path tokens (ADR 0005, ticket #202).

A Remote session's path token lives 5 min unless its Session bar renews it.
The Portal asks each open Session bar to renew every 60 s (a status message
with ``renew``) and the bar answers over its status channel; the harness's
status channel answers just as the page's script does, unless told not to.
Time is virtual: the agent and the Portal share the fake clock.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import timedelta

import pytest

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import PORTAL_OWNER, Browser, Portal
from .harness.server import serving
from .harness.session_bar import status_channel
from .test_base_proxy import FRAMED
from .test_tunnel import base_of, eventually, open_remotely, wait_tunnel

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
async def agent(
    portal: Portal, operator: Browser, server: int
) -> AsyncIterator[RunningAgent]:
    ui: BaseUi
    async with (
        base_ui() as ui,
        # A polling base (protocol version 1): its tunnel closes with the
        # last Remote session, which these tests watch for.
        running_agent(
            portal, server_port=server, app_port=ui.port, protocol_version=1
        ) as a,
    ):
        await a.claim(operator)
        yield a


async def test_a_renewed_token_keeps_working_and_is_refused_5_min_after_the_last_renewal(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)
        frame = (await bar.until("connected"))["frame"]

        for _ in range(12):  # renewed all along
            await agent.run(minutes=1)
            await asyncio.sleep(0.05)  # the Portal asks, the bar answers
        assert bar.renewals >= 10
        assert (await operator.get(frame, headers=FRAMED)).status_code == 200

        bar.renewing = False  # the bar is gone, but its channel stays open
        await bar.renew()  # the last renewal: 5 min from now
        expires = (portal.clock.now() + timedelta(minutes=5)).isoformat()
        await eventually(
            lambda: bar.messages[-1].get("lease_expires_at") == expires,
            "the Portal answered the renewal",
        )
        await agent.run(minutes=4, seconds=59)
        assert (await operator.get(frame, headers=FRAMED)).status_code == 200

        await agent.run(seconds=1)
        assert (await operator.get(frame, headers=FRAMED)).status_code == 403
        ended = await bar.until("ended")

    assert ended["reason"] == "lease_expired"
    assert "frame" not in ended
    await wait_tunnel(agent, "closed")


async def test_an_expired_lease_ends_the_remote_session_and_is_audited(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        bar.renewing = False
        await agent.run(seconds=20)
        await bar.until("connected")
        await agent.run(minutes=5)
        await bar.until("ended")

    [session] = await portal.query("SELECT id, end_reason FROM remote_session")
    assert session["end_reason"] == "lease_expired"
    entries = await portal.query(
        "SELECT detail FROM audit_entry WHERE kind = 'remote_session_end'"
    )
    assert [e["detail"] for e in entries] == [
        {"remote_session": session["id"], "reason": "lease_expired"}
    ]
    audit = (await operator.get("/audit")).text
    assert "lease expired" in audit


async def test_a_paused_remote_session_is_not_renewed(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)
        frame = (await bar.until("connected"))["frame"]
        await agent.run(minutes=60)  # the hard cap pauses it
        paused = await bar.until("ended")
        assert paused["reason"] == "hard_cap"
        asked = [m for m in bar.messages if m.get("renew")]
        assert asked and not paused.get("renew")
        renewals = bar.renewals
        await agent.run(minutes=5)
        assert bar.renewals == renewals
        assert (await operator.get(frame, headers=FRAMED)).status_code == 403

    rows = await portal.query("SELECT end_reason FROM remote_session")
    assert rows == [{"end_reason": "hard_cap"}]


@pytest.fixture
async def owner(portal: Portal, authentik: FakeAuthentik) -> AsyncIterator[Browser]:
    authentik.add_user(PORTAL_OWNER, PASSWORD)
    async with portal.browser() as b:
        assert (await b.sign_in(PORTAL_OWNER, PASSWORD)).json() == {"next": "/"}
        yield b


async def test_the_portal_owner_sets_the_lease_in_the_agent_config(
    owner: Browser, operator: Browser, agent: RunningAgent, server: int
):
    for refused in (
        {"lease_length": "30"},
        {"lease_renewal_interval": "300"},  # not shorter than the lease
    ):
        resp = await owner.action("/settings/agent-config", refused)
        assert resp.status_code == 400, refused
    resp = await owner.action(
        "/settings/agent-config",
        {"lease_length": "120", "lease_renewal_interval": "30"},
    )
    assert resp.status_code == 200, resp.text

    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)
        await bar.until("connected")
        await agent.run(seconds=40)
        assert bar.renewals >= 1  # asked every 30 s

        bar.renewing = False
        await agent.run(minutes=2)
        ended = await bar.until("ended")

    assert ended["reason"] == "lease_expired"
