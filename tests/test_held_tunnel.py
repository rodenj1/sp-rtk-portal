"""Seam 1: a Claimed base holds its tunnel open (ADR 0006, protocol
version 2, ticket #204).

The real agent opens its tunnel on Claim and on start, with no Wake, and
keeps it open: it pings every 50 s and the Portal never pings. The Portal
closes a held tunnel that sent nothing for 120 s, and a new one from the
same base replaces the old. Open remotely on a holding base reaches the
base's UI at once; each Remote session keeps its own idle close and hard
cap while the tunnel stays open.

The Portal is served over real TCP (websockets); the agent runs on virtual
time; the stub playing the base's UI records every request that reaches it.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import timedelta

import pytest
from sp_rtk_portal_protocol import PROTOCOL_VERSION, VERSION_HEADER, BaseKey, Stream
from sp_rtk_portal_protocol.tunnel import Frame, Kind, encode
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.fake_authentik import FakeAuthentik
from .harness.pages import base_card
from .harness.portal import ORIGIN, Browser, Portal
from .harness.server import serving
from .harness.session_bar import status_channel

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


async def wait_tunnel(agent: RunningAgent, state: str) -> None:
    async def reached() -> bool:
        return (await agent.status()).tunnel == state

    await eventually(reached, f"the agent's tunnel {state}")


async def held(portal: Portal, agent: RunningAgent) -> str:
    """Wait until both ends see the base's tunnel open; its base id."""
    base_id = await base_of(agent)
    await wait_tunnel(agent, "open")
    await eventually(
        lambda: portal.context.tunnels.tunnel_up(base_id), "the Portal sees it"
    )
    return base_id


def pings(agent: RunningAgent, *, sent: bool) -> list[timedelta]:
    """When the agent sent (or received) a PING, from its first one."""
    times = [f.at for f in agent.frames if f.kind == Kind.PING and f.sent == sent]
    return [t - times[0] for t in times]


# --- Holding the tunnel ------------------------------------------------------------


async def test_after_claim_the_agent_holds_its_tunnel_for_hours_pinging_every_50_s(
    portal: Portal, agent: RunningAgent
):
    base_id = await held(portal, agent)
    assert portal.context.tunnels.wake_for_poll(base_id) is None  # no Wake
    assert (await agent.status()).connection_mode == "holding"

    await agent.run(hours=3)

    assert portal.context.tunnels.tunnel_up(base_id)
    assert agent.tunnel_urls == [TUNNEL_URL]  # opened once, never again
    sent = pings(agent, sent=True)
    assert len(sent) == 3 * 3600 // 50
    assert sent == [timedelta(seconds=50 * i) for i in range(len(sent))]
    assert pings(agent, sent=False) == []  # the Portal never pings


async def test_the_agent_holds_its_tunnel_again_after_a_restart(
    portal: Portal, agent: RunningAgent
):
    base_id = await held(portal, agent)

    await agent.restart()

    assert await held(portal, agent) == base_id
    assert agent.tunnel_urls == [TUNNEL_URL] * 2


# --- Remote sessions on a holding base ---------------------------------------------


async def open_remotely(browser: Browser, base_id: str) -> None:
    resp = await browser.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}, resp.text


async def read_all(stream: Stream) -> bytes:
    data = b""
    while chunk := await asyncio.wait_for(stream.read(), 5):
        data += chunk
    return data


async def test_open_remotely_on_a_holding_base_reaches_its_ui_with_no_wake(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int, ui: BaseUi
):
    base_id = await held(portal, agent)

    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await bar.until("connected")  # at once: no virtual time passed
    assert portal.context.tunnels.wake_for_poll(base_id) is None

    stream = await portal.context.tunnels.open_stream(base_id)
    await stream.write(b"GET /survey HTTP/1.1\r\nHost: portal\r\n\r\n")
    assert (await read_all(stream)).endswith(b"base page /survey")
    assert [(s.method, s.path) for s in ui.seen] == [("GET", "/survey")]
    assert agent.tunnel_urls == [TUNNEL_URL]


async def test_idle_close_and_hard_cap_end_each_remote_session_not_the_tunnel(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await held(portal, agent)
    [account] = await portal.query("SELECT id FROM account WHERE email = %s", EMAIL)
    tunnels = portal.context.tunnels

    # Idle: 2 min after its Session bar closed, the Remote session ends.
    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await bar.until("connected")
    await agent.run(seconds=110)
    await asyncio.sleep(0.1)
    assert tunnels.session_for(account["id"], base_id) is not None
    await agent.run(seconds=10)
    await eventually(
        lambda: tunnels.session_for(account["id"], base_id) is None, "idle end"
    )

    # Hard cap: 60 min after it started, however busy.
    await open_remotely(operator, base_id)
    async with status_channel(server, operator, base_id) as bar:
        await bar.until("connected")
        await agent.run(minutes=60)
        ended = await bar.until("ended")
    assert ended["reason"] == "hard_cap"

    # The tunnel stayed up throughout, and stays up.
    await agent.run(minutes=10)
    assert tunnels.tunnel_up(base_id)
    assert agent.tunnel_urls == [TUNNEL_URL]
    rows = await portal.query("SELECT end_reason FROM remote_session ORDER BY id")
    assert [r["end_reason"] for r in rows] == ["left", "hard_cap"]


# --- The Portal's end: silence, replacement, refusals ------------------------------


async def hand_open(
    portal: Portal,
    server: int,
    key: BaseKey,
    *,
    nonce: str | None = None,
    version: int = PROTOCOL_VERSION,
    tamper: Callable[[str], str] = lambda authorization: authorization,
) -> ClientConnection:
    """Open a tunnel by hand, as the base's agent would (or a forger)."""
    authorization = key.authorization(
        "GET", ORIGIN + "/agent/tunnel", now=portal.clock.now(), nonce=nonce
    )
    return await connect(
        f"ws://127.0.0.1:{server}/agent/tunnel",
        additional_headers={
            VERSION_HEADER: str(version),
            "Authorization": tamper(authorization),
        },
    )


async def refused(opening: Awaitable[object]) -> int:
    with pytest.raises(InvalidStatus) as caught:
        await opening
    return caught.value.response.status_code


async def closes(ws: ClientConnection) -> bool:
    """The Portal closes ``ws`` (passing over its control messages)."""
    with pytest.raises(ConnectionClosed):
        while True:
            message = await asyncio.wait_for(ws.recv(), 5)
            assert isinstance(message, bytes) and message[0] == Kind.CONTROL
    return True


async def test_a_new_tunnel_from_the_base_replaces_the_old_and_120_s_of_silence_closes_it(
    portal: Portal, agent: RunningAgent, server: int
):
    base_id = await held(portal, agent)
    tunnels = portal.context.tunnels

    # A second tunnel from the same base (here, opened by hand) replaces it.
    second = await hand_open(portal, server, agent.key)
    await wait_tunnel(agent, "closed")
    assert tunnels.tunnel_up(base_id)

    # The hand-opened one never pings: the Portal closes it after 120 s.
    portal.clock.advance(seconds=119)
    await asyncio.sleep(0.1)  # a few sweeps
    assert tunnels.tunnel_up(base_id)
    portal.clock.advance(seconds=1)
    assert await closes(second)
    await eventually(lambda: not tunnels.tunnel_up(base_id), "the Portal closed it")


async def test_a_tunnel_open_without_a_nonce_is_refused_from_v1_unclaimed_or_forged(
    portal: Portal, agent: RunningAgent, server: int
):
    await held(portal, agent)

    assert await refused(hand_open(portal, server, agent.key, version=1)) == 403
    assert await refused(hand_open(portal, server, BaseKey.generate())) == 403
    forged = await refused(
        hand_open(portal, server, agent.key, tamper=lambda a: a[:-4] + "AAAA")
    )
    assert forged == 403

    opened = await hand_open(portal, server, agent.key)  # the real thing
    await opened.close()


# --- Online state and connection mode ----------------------------------------------


async def card(operator: Browser, base_id: str) -> tuple[str, str]:
    """The base list's online state and connection for the base."""
    found = base_card((await operator.get("/")).text, base_id)
    return found["state"][0], found["connection"][0]


async def test_a_holding_base_is_online_while_connected_and_2_min_after_a_drop(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int
):
    base_id = await held(portal, agent)
    assert await card(operator, base_id) == ("Online", "Holding its tunnel")

    # Only a tunnel that pings is left (the agent's polls stop): the base
    # stays online however long ago it last polled.
    await agent.stop()
    tunnel = await hand_open(portal, server, agent.key)
    await eventually(lambda: portal.context.tunnels.tunnel_up(base_id), "held")
    for _ in range(12):
        portal.clock.advance(seconds=50)
        await tunnel.send(encode(Frame(Kind.PING, 0)))
        await tunnel.recv()  # its PONG
    assert await card(operator, base_id) == ("Online", "Holding its tunnel")

    # It drops: online for 2 min after the last ping, then offline.
    await tunnel.close()
    await eventually(lambda: not portal.context.tunnels.tunnel_up(base_id), "gone")
    portal.clock.advance(seconds=120)
    assert await card(operator, base_id) == ("Online", "Reconnecting its tunnel")
    portal.clock.advance(seconds=1)
    assert (await card(operator, base_id))[0] == "Offline"


# --- Version 1 agents ----------------------------------------------------------------


async def test_a_version_1_agent_still_polls_and_opens_its_tunnel_only_on_a_wake(
    portal: Portal, operator: Browser, server: int, ui: BaseUi
):
    async with running_agent(
        portal, server_port=server, app_port=ui.port, protocol_version=1
    ) as old:
        await old.claim(operator)
        base_id = await base_of(old)
        await old.run(minutes=5)
        assert old.tunnel_urls == []
        assert (await old.status()).connection_mode == "polling"
        assert await card(operator, base_id) == ("Online", "Polling every 20 s")

        await open_remotely(operator, base_id)
        async with status_channel(server, operator, base_id) as bar:
            await bar.until("waking")
            await old.run(seconds=20)  # the next poll carries the Wake
            await bar.until("connected")
        assert old.tunnel_urls == [TUNNEL_URL]

        # Its tunnel still closes with its last Remote session.
        await old.run(minutes=2)
        await wait_tunnel(old, "closed")
