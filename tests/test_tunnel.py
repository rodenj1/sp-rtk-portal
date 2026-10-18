"""Seam 1: "Open remotely" Wakes the base, the real agent opens its tunnel
through the Portal, and streams reach the base's UI and nothing else
(ticket #88).

The Portal is served over real TCP (websockets); the agent runs on virtual
time, so a Wake is picked up exactly when its next poll would go out. The
stub playing the base's UI records every request that reaches it.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import timedelta

import pytest
from sp_rtk_portal_protocol import (
    PROTOCOL_VERSION,
    VERSION_HEADER,
    BaseKey,
    Stream,
)
from sp_rtk_portal_protocol import tunnel as framing
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus
from wsproto import ConnectionType, WSConnection
from wsproto.events import (
    AcceptConnection,
    CloseConnection,
    Message,
    Request,
    TextMessage,
)

from sp_rtk_portal.tunnel.end_reason import EndReason

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import ORIGIN, Browser, Portal
from .harness.server import serving
from .harness.session_bar import status_channel

EMAIL = "operator@example.com"
OTHER = "colleague@example.com"
PASSWORD = "correct horse battery staple"
TUNNEL_URL = "wss://sp-rtk-base.big-spray.com/agent/tunnel"
IP = "198.51.100.66"


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


async def open_remotely(browser: Browser, base_id: str) -> None:
    resp = await browser.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}, resp.text


async def tunnel_state(agent: RunningAgent) -> str | None:
    return (await agent.status()).tunnel


async def wait_tunnel(agent: RunningAgent, state: str) -> None:
    async def reached() -> bool:
        return await tunnel_state(agent) == state

    await eventually(reached, f"the agent's tunnel {state}")


async def read_all(stream: Stream) -> bytes:
    data = b""
    while chunk := await asyncio.wait_for(stream.read(), 5):
        data += chunk
    return data


@pytest.fixture
async def colleague(portal: Portal, authentik: FakeAuthentik) -> AsyncIterator[Browser]:
    """Another signed-in user, who doesn't own the base."""
    authentik.add_user(OTHER, PASSWORD)
    async with portal.browser(ip="203.0.113.99") as b:
        assert (await b.sign_in(OTHER, PASSWORD)).json() == {"next": "/"}
        yield b


# --- Wake and tunnel ---------------------------------------------------------------


async def test_open_remotely_wakes_the_base_and_its_streams_reach_the_base_ui(
    portal: Portal,
    operator: Browser,
    agent: RunningAgent,
    server: int,
    ui: BaseUi,
):
    base_id = await base_of(agent)

    await open_remotely(operator, base_id)
    page = await operator.get(f"/bases/{base_id}")
    assert "Waking North field" in page.text
    assert "checks for requests every 20 s" in page.text

    async with status_channel(server, operator, base_id) as bar:
        assert (await bar.until("waking"))["state"] == "waking"
        await agent.run(seconds=20)  # the next poll carries the Wake
        await bar.until("connected")

    assert agent.tunnel_urls == [TUNNEL_URL]
    assert await tunnel_state(agent) == "open"

    # An HTTP request down a stream...
    stream = await portal.context.tunnels.open_stream(base_id)
    await stream.write(
        b"GET /survey HTTP/1.1\r\nHost: sp-rtk-base.big-spray.com\r\n"
        b"X-Forwarded-Prefix: /b/x/s/y\r\n\r\n"
    )
    response = await read_all(stream)
    assert response.startswith(b"HTTP/1.1 200")
    assert response.endswith(b"base page /survey")

    # ...and a websocket.
    stream = await portal.context.tunnels.open_stream(base_id)
    ws = WSConnection(ConnectionType.CLIENT)
    await stream.write(ws.send(Request(host="sp-rtk-base.big-spray.com", target="/ws")))
    events: list[object] = []
    while not any(isinstance(e, AcceptConnection) for e in events):
        ws.receive_data(await asyncio.wait_for(stream.read(), 5))
        events += list(ws.events())
    await stream.write(ws.send(Message(data="hello")))
    reply = ""
    while not reply:
        ws.receive_data(await asyncio.wait_for(stream.read(), 5))
        reply = "".join(e.data for e in ws.events() if isinstance(e, TextMessage))
    await stream.write(ws.send(CloseConnection(code=1000)))
    assert reply == "echo hello"

    assert [(s.method, s.path, s.host) for s in ui.seen] == [
        ("GET", "/survey", "localhost:8080"),
        ("WEBSOCKET", "/ws", "localhost:8080"),
    ]
    assert ui.seen[0].headers["x-forwarded-prefix"] == "/b/x/s/y"


async def test_the_wake_rides_on_the_poll_and_nothing_opens_without_one(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    await agent.run(minutes=2)
    assert agent.tunnel_urls == []
    assert await tunnel_state(agent) == "closed"

    await open_remotely(operator, await base_of(agent))
    await agent.run(seconds=20)
    await wait_tunnel(agent, "open")
    assert agent.tunnel_urls == [TUNNEL_URL]


# --- Refused opens -----------------------------------------------------------------


async def hand_open(
    portal: Portal,
    server: int,
    key: BaseKey | None,
    nonce: str | None,
    ip: str | None = None,
) -> object:
    headers = {VERSION_HEADER: str(PROTOCOL_VERSION)}
    if ip is not None:
        headers["CF-Connecting-IP"] = ip
    if key is not None:
        headers["Authorization"] = key.authorization(
            "GET",
            ORIGIN + "/agent/tunnel",
            now=portal.clock.now(),
            nonce=nonce,
        )
    return await connect(
        f"ws://127.0.0.1:{server}/agent/tunnel", additional_headers=headers
    )


async def refused(opening: Awaitable[object]) -> int:
    with pytest.raises(InvalidStatus) as caught:
        await opening
    return caught.value.response.status_code


async def test_a_tunnel_open_with_a_wrong_or_reused_nonce_or_unsigned_is_refused(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    nonce = portal.context.tunnels.wake(base_id)  # the pending Wake's nonce

    assert await refused(hand_open(portal, server, None, nonce)) == 403
    assert await refused(hand_open(portal, server, agent.key, "guessed")) == 403
    assert await refused(hand_open(portal, server, agent.key, None)) == 403
    assert await refused(hand_open(portal, server, BaseKey.generate(), nonce)) == 403

    opened = await hand_open(portal, server, agent.key, nonce)  # the real thing
    await opened.close()  # type: ignore[attr-defined]
    assert await refused(hand_open(portal, server, agent.key, nonce)) == 403


async def test_after_too_many_refused_opens_an_ip_is_refused_outright_for_an_hour(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    ctx = portal.context
    ctx.settings = dataclasses.replace(ctx.settings, tunnel_refusals_per_ip=3)
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    nonce = portal.context.tunnels.wake(base_id)
    for _ in range(3):  # e.g. replaying forged Wakes
        assert await refused(hand_open(portal, server, agent.key, "x", ip=IP)) == 403

    # Now even a good open from there is refused; elsewhere is unaffected.
    assert await refused(hand_open(portal, server, agent.key, nonce, ip=IP)) == 403
    opened = await hand_open(portal, server, agent.key, nonce, ip="198.51.100.77")
    await opened.close()  # type: ignore[attr-defined]

    portal.clock.advance(minutes=60)
    nonce = portal.context.tunnels.wake(base_id)
    opened = await hand_open(portal, server, agent.key, nonce, ip=IP)
    await opened.close()  # type: ignore[attr-defined]


async def test_a_forged_poll_reply_cannot_point_the_tunnel_at_another_host(
    portal: Portal, operator: Browser, agent: RunningAgent, ui: BaseUi
):
    # Play a compromised Portal: an agent config naming another tunnel host.
    await portal.query(
        "INSERT INTO agent_config (revision, config, created_at) VALUES (2, %s, %s)",
        '{"revision": 2, "tunnel_url": "wss://attacker.example/agent/tunnel"}',
        portal.clock.now(),
    )
    await agent.run(seconds=20)
    assert (await agent.status()).config_revision == 2

    await open_remotely(operator, await base_of(agent))
    await agent.run(seconds=20)
    await wait_tunnel(agent, "open")

    assert agent.tunnel_urls == [TUNNEL_URL]


# --- Frames that close the tunnel --------------------------------------------------


@pytest.mark.parametrize(
    ("compromise", "logged"),
    [
        (lambda raw: raw + b"192.168.1.5:22", "NEW frame carries"),
        (lambda raw: raw + b'{"host": "nas.lan", "port": 445}', "NEW frame carries"),
        (lambda raw: b"\x2a" + raw[1:], "unknown frame type 42"),
    ],
)
async def test_a_stream_frame_with_a_destination_or_an_unknown_frame_closes_the_tunnel(
    portal: Portal,
    operator: Browser,
    agent: RunningAgent,
    ui: BaseUi,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    compromise: Callable[[bytes], bytes],
    logged: str,
):
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)
    await agent.run(seconds=20)
    await wait_tunnel(agent, "open")

    # Play a compromised Portal whose new-stream frames carry more.
    honest = framing.encode

    def compromised(frame: framing.Frame) -> bytes:
        raw = honest(frame)
        return compromise(raw) if frame.kind == framing.Kind.NEW else raw

    monkeypatch.setattr(framing, "encode", compromised)
    with caplog.at_level(logging.WARNING, logger="sp_rtk_base.portal_agent"):
        await portal.context.tunnels.open_stream(base_id)
        await wait_tunnel(agent, "closed")

    assert logged in caplog.text
    assert ui.seen == []
    await eventually(
        lambda: not portal.context.tunnels.tunnel_up(base_id), "Portal sees it closed"
    )


# --- Sharing, idle close and hard cap ----------------------------------------------


async def test_two_remote_sessions_share_one_tunnel_which_closes_2_min_after_the_last_leaves(
    portal: Portal,
    operator: Browser,
    colleague: Browser,
    agent: RunningAgent,
    server: int,
):
    base_id = await base_of(agent)
    [row] = await portal.query("SELECT id FROM account WHERE email = %s", OTHER)
    # Shares (#91) will let a Shared user open it from their list; until then
    # the colleague's Remote session is started through the broker directly.
    tunnels = portal.context.tunnels

    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as mine:
        await agent.run(seconds=20)
        await mine.until("connected")
        await tunnels.start_session(row["id"], base_id, "203.0.113.99")
        async with status_channel(server, colleague, base_id) as theirs:
            await theirs.until("connected")
            assert agent.tunnel_urls == [TUNNEL_URL]  # one tunnel for both
            assert tunnels.session_for(row["id"], base_id) is not None
        # The colleague left; the Operator stays well past the idle timeout.
        await agent.run(minutes=5)
        await eventually(
            lambda: tunnels.session_for(row["id"], base_id) is None,
            "the colleague's session ended",
        )
        assert await tunnel_state(agent) == "open"
        assert mine.state == "connected"

    # The last one left: open for 2 min more, then closed.
    await agent.run(seconds=110)
    await asyncio.sleep(0.1)
    assert await tunnel_state(agent) == "open"
    await agent.run(seconds=10)
    await wait_tunnel(agent, "closed")
    assert not tunnels.tunnel_up(base_id)

    # It reopens on the next Wake. (Earlier opens may include the agent's
    # own idle backstop: no frame here keeps a stream open, so it closed the
    # tunnel and the Portal re-Woke the base.)
    opened = len(agent.tunnel_urls)
    await open_remotely(operator, base_id)
    await agent.run(seconds=20)
    await wait_tunnel(agent, "open")
    assert agent.tunnel_urls == [TUNNEL_URL] * (opened + 1)


async def test_a_users_tabs_share_one_remote_session(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    [account] = await portal.query("SELECT id FROM account WHERE email = %s", EMAIL)

    await open_remotely(operator, base_id)
    first = portal.context.tunnels.session_for(account["id"], base_id)
    await open_remotely(operator, base_id)  # another tab
    second = portal.context.tunnels.session_for(account["id"], base_id)

    assert first is second
    assert first is not None and len(first.token) >= 22  # >= 128 bits
    rows = await portal.query("SELECT id FROM remote_session")
    assert len(rows) == 1


async def test_the_60_min_hard_cap_ends_the_remote_session_and_revokes_its_token(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    [account] = await portal.query("SELECT id FROM account WHERE email = %s", EMAIL)
    tunnels = portal.context.tunnels
    await open_remotely(operator, base_id)
    session = tunnels.session_for(account["id"], base_id)
    assert session is not None
    token = session.token

    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)
        await bar.until("connected")
        await agent.run(minutes=59)
        assert tunnels.lookup(base_id, token) is session
        await agent.run(seconds=40)
        ended = await bar.until("ended")

    assert ended["reason"] == "hard_cap"
    assert tunnels.lookup(base_id, token) is None
    assert tunnels.session_for(account["id"], base_id) is None
    await wait_tunnel(agent, "closed")


async def test_remote_session_start_and_end_are_audited_with_who_base_time_and_ip(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    [account] = await portal.query("SELECT id FROM account WHERE email = %s", EMAIL)
    started_at = portal.clock.now()

    await open_remotely(operator, base_id)
    await agent.run(seconds=20)
    await agent.run(minutes=3)  # nobody opened the Session bar: it ends
    await eventually(
        lambda: portal.context.tunnels.session_for(account["id"], base_id) is None,
        "the session ended",
    )

    entries = await portal.query(
        "SELECT kind, account_id, base_id, host(ip) AS ip, at, detail"
        " FROM audit_entry WHERE kind LIKE 'remote_session%%' ORDER BY id"
    )
    assert [(e["kind"], e["account_id"], e["base_id"], e["ip"]) for e in entries] == [
        ("remote_session_start", account["id"], base_id, "203.0.113.7"),
        ("remote_session_end", account["id"], base_id, "203.0.113.7"),
    ]
    assert entries[0]["at"] == started_at
    assert entries[1]["at"] - started_at >= timedelta(minutes=2)
    assert entries[1]["detail"]["reason"] == "left"
    assert (
        entries[0]["detail"]["remote_session"] == entries[1]["detail"]["remote_session"]
    )


async def test_ending_inside_a_failing_transaction_still_ends_and_records_it(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    # Callers end Remote sessions inside their own transaction (an Un-claim,
    # a pause...); the end, and its record, stand whatever becomes of it.
    base_id = await base_of(agent)
    [account] = await portal.query("SELECT id FROM account WHERE email = %s", EMAIL)
    tunnels = portal.context.tunnels
    await open_remotely(operator, base_id)
    session = tunnels.session_for(account["id"], base_id)
    assert session is not None

    with pytest.raises(RuntimeError, match="the caller's transaction fails"):
        async with portal.context.db.connection():
            await tunnels.end_for_base(base_id, EndReason.PAUSED)
            raise RuntimeError("the caller's transaction fails")

    assert tunnels.state(session) == "ended"
    assert tunnels.lookup(base_id, session.token) is None
    assert tunnels.session_for(account["id"], base_id) is None
    rows = await portal.query(
        "SELECT end_reason FROM remote_session WHERE id = %s", session.id
    )
    assert rows == [{"end_reason": "paused"}]
    ends = await portal.query(
        "SELECT detail FROM audit_entry WHERE kind = 'remote_session_end'"
    )
    assert [e["detail"]["reason"] for e in ends] == ["paused"]
    # And the user opens the base again (one live row per account and base).
    await open_remotely(operator, base_id)
    assert tunnels.session_for(account["id"], base_id) is not None


async def test_only_a_user_who_may_reach_the_base_can_open_it(
    colleague: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    stranger = colleague

    resp = await stranger.action(f"/bases/{base_id}/remote")
    assert resp.status_code == 404
    assert (await stranger.get(f"/bases/{base_id}")).status_code == 404
    with pytest.raises(InvalidStatus):
        async with status_channel(server, stranger, base_id):
            pass


async def test_the_status_channel_refuses_another_origin(
    operator: Browser, agent: RunningAgent, server: int
):
    base_id = await base_of(agent)
    await open_remotely(operator, base_id)

    for origin in ("null", "https://evil.example"):
        with pytest.raises(InvalidStatus):
            async with status_channel(server, operator, base_id, origin=origin):
                pass
