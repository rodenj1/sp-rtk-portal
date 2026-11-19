"""Seam 1: remote access paused on site (tickets #92, #207).

The Operator pauses remote access on the base's local Portal page. The real
agent keeps its Claim, keeps polling and Checking in, reports ``paused`` and
ignores Wakes; it keeps its held tunnel but ends the open streams and
refuses every new one. The Portal shows "Remote access paused", refuses
Open remotely and ends the base's live Remote sessions. Only the base can
resume, on the same tunnel. The agent also learns from each poll who is
using the base remotely.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime

import pytest
from sp_rtk_portal_protocol import CHECK_IN_PATH, CheckIn, Stream, read_control
from sp_rtk_portal_protocol.tunnel import Kind
from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection, Request

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
TUNNEL_URL = "wss://sp-rtk-base.big-spray.com/agent/tunnel"


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
async def polling_agent(
    portal: Portal, operator: Browser, server: int, ui: BaseUi
) -> AsyncIterator[RunningAgent]:
    """An agent that only polls and answers Wakes (protocol version 1)."""
    async with running_agent(
        portal, server_port=server, app_port=ui.port, protocol_version=1
    ) as a:
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
    """Check-ins say whether remote access is paused too, so a base that
    rarely polls still tells the Portal."""
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


async def test_a_paused_polling_agent_opens_no_tunnel_for_a_wake_sent_anyway(
    portal: Portal, operator: Browser, polling_agent: RunningAgent
):
    agent = polling_agent
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


async def held(portal: Portal, agent: RunningAgent) -> str:
    """Wait until both ends see the base's tunnel open; its base id."""
    base_id = await base_of(agent)

    async def open_here() -> bool:
        return (await agent.status()).tunnel == "open"

    await eventually(open_here, "the agent's tunnel open")
    await eventually(
        lambda: portal.context.tunnels.tunnel_up(base_id), "the Portal sees it"
    )
    return base_id


def check_ins_since(agent: RunningAgent, since: datetime) -> int:
    """Check-ins ``agent`` sent since ``since``: on its held tunnel, or
    accepted over HTTPS."""
    on_tunnel = sum(
        1
        for f in agent.frames
        if f.sent
        and f.kind == Kind.CONTROL
        and f.at > since
        and isinstance(read_control(f.payload), CheckIn)
    )
    over_https = sum(
        1
        for r in agent.requests
        if r.path == CHECK_IN_PATH and r.status == 200 and r.at > since
    )
    return on_tunnel + over_https


async def read_all(stream: Stream) -> bytes:
    data = b""
    while chunk := await asyncio.wait_for(stream.read(), 5):
        data += chunk
    return data


async def open_websocket(stream: Stream) -> WSConnection:
    """Open a websocket to the base's UI down ``stream``: a stream that
    stays open until one side ends it."""
    ws = WSConnection(ConnectionType.CLIENT)
    await stream.write(ws.send(Request(host="sp-rtk-base.big-spray.com", target="/ws")))
    events: list[object] = []
    while not any(isinstance(e, AcceptConnection) for e in events):
        ws.receive_data(await asyncio.wait_for(stream.read(), 5))
        events += list(ws.events())
    return ws


async def test_pausing_ends_remote_sessions_and_their_streams_but_keeps_the_tunnel(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int, ui: BaseUi
):
    base_id = await held(portal, agent)
    tunnels = portal.context.tunnels
    [account] = await portal.query("SELECT id FROM account WHERE email = %s", EMAIL)
    await operator.action(f"/bases/{base_id}/remote")
    session = tunnels.session_for(account["id"], base_id)
    assert session is not None

    async with status_channel(server, operator, base_id) as bar:
        await bar.until("connected")
        stream = await tunnels.open_stream(base_id)
        await open_websocket(stream)
        paused_at = portal.clock.now()

        await agent.pause()

        ended = await bar.until("ended")
        assert await read_all(stream) == b""  # the open stream ended too

    assert ended["reason"] == "paused"
    page = fields((await operator.get(f"/bases/{base_id}")).text)
    assert page["status"] == ["Remote access paused"]
    assert "remote-paused" in page
    assert tunnels.lookup(base_id, session.token) is None
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

    # The tunnel stays open, and the base keeps Checking in.
    await agent.run(minutes=15)
    assert tunnels.tunnel_up(base_id)
    status = await agent.status()
    assert (status.tunnel, status.connection_mode) == ("open", "holding")
    assert agent.tunnel_urls == [TUNNEL_URL]  # never reopened
    assert check_ins_since(agent, paused_at) >= 2
    assert (await card(operator, base_id))[0] == "paused"

    await agent.resume()
    entries = await portal.query(
        "SELECT kind FROM audit_entry WHERE kind = 'remote_access_resumed'"
    )
    assert len(entries) == 1


async def test_a_paused_base_refuses_a_stream_before_it_reaches_the_ui(
    portal: Portal, agent: RunningAgent, ui: BaseUi
):
    base_id = await held(portal, agent)
    await agent.pause()

    stream = await portal.context.tunnels.open_stream(base_id)  # as a buggy Portal
    await stream.write(b"GET /survey HTTP/1.1\r\nHost: portal\r\n\r\n")

    assert await read_all(stream) == b""
    assert ui.seen == []
    assert portal.context.tunnels.tunnel_up(base_id)


async def test_resuming_reenables_open_remotely_on_the_same_tunnel(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int, ui: BaseUi
):
    base_id = await held(portal, agent)
    await agent.pause()
    state, f = await card(operator, base_id)
    assert (state, f["state"]) == ("paused", ["Remote access paused"])
    assert "open-remotely@disabled" in f

    await agent.resume()

    state, f = await card(operator, base_id)
    assert (state, f["state"]) == ("online", ["Online"])
    assert "open-remotely@disabled" not in f
    resp = await operator.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}
    async with status_channel(server, operator, base_id) as bar:
        await bar.until("connected")  # at once: no reconnect, no Wake
    stream = await portal.context.tunnels.open_stream(base_id)
    await stream.write(b"GET /survey HTTP/1.1\r\nHost: portal\r\n\r\n")
    assert (await read_all(stream)).endswith(b"base page /survey")
    assert agent.tunnel_urls == [TUNNEL_URL]


async def test_the_agent_learns_who_is_connected_remotely_and_since_when(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    started = portal.clock.now()

    await operator.action(f"/bases/{base_id}/remote")

    async def told() -> bool:
        return bool((await agent.status()).sessions)

    await eventually(told, "the agent hears of it on its tunnel")
    [session] = (await agent.status()).sessions
    assert (session.who, session.since, session.shared) == (EMAIL, started, False)
