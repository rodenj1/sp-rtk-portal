"""Seam 1: a base whose network won't let its tunnel open falls back to
polling (ticket #209).

After 3 tunnel opens fail in a row while an ordinary signed HTTPS request
(a Check-in) gets through, the agent polls at the configured interval, the
Portal Wakes it as it Wakes any polling base, and every 15 min it tries its
tunnel again, holding it once it opens. When its HTTPS fails too, nothing
says the network is the problem rather than the Portal: it keeps backing
off on the tunnel instead. The Portal logs how many bases are in each
connection mode.

The Portal is served over real TCP (websockets); the agent runs on virtual
time, its HTTPS over a real wire that counts connections
(:mod:`.harness.wire`); ``agent.upgrades_refused`` plays a proxy that
refuses websocket upgrades and lets HTTPS through.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
from sp_rtk_portal_protocol import PROTOCOL_VERSION

from .harness.agent import RunningAgent, running_agent
from .harness.agent_time import AgentTime
from .harness.base_ui import BaseUi, base_ui
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser, Portal
from .harness.server import serving
from .harness.session_bar import status_channel
from .harness.wire import Wire, wire

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
async def https(portal: Portal) -> AsyncIterator[Wire]:
    async with wire(portal) as w:
        yield w


@pytest.fixture
async def agent(
    portal: Portal, operator: Browser, server: int, ui: BaseUi, https: Wire
) -> AsyncIterator[RunningAgent]:
    """A Claimed base holding its tunnel, its HTTPS over the wire."""
    async with running_agent(
        portal, server_port=server, app_port=ui.port, transport=https.transport
    ) as a:
        await a.claim(operator)
        await mode(a, "holding")
        yield a


async def eventually(check: Callable[[], Awaitable[bool] | bool], what: str) -> None:
    for _ in range(500):
        result = check()
        if isinstance(result, Awaitable):
            result = await result
        if result:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"never: {what}")


async def mode(agent: RunningAgent, expected: str) -> None:
    """Wait until the agent says it is in this connection mode."""

    async def reached() -> bool:
        return (await agent.status()).connection_mode == expected

    await eventually(reached, f"the agent is {expected}")


async def drop(agent: RunningAgent) -> int:
    """The network drops the tunnel; how many opens were tried by then."""
    agent.drop_tunnel()

    async def closed() -> bool:
        return (await agent.status()).tunnel == "closed"

    await eventually(closed, "the agent sees its tunnel closed")
    return len(agent.tunnel_attempts)


async def falls_back(agent: RunningAgent) -> int:
    """Upgrades are refused from now, and the tunnel drops: let time run
    until the agent polls. Returns how many opens it had tried by then."""
    agent.upgrades_refused = True
    tried = await drop(agent)
    for _ in range(60):
        await agent.run(seconds=20)
        if (await agent.status()).connection_mode == "polling":
            return tried
    raise AssertionError("the agent never fell back to polling")


async def test_after_3_refused_upgrades_the_agent_polls_on_one_reused_connection(
    agent: RunningAgent, https: Wire
):
    tried = await falls_back(agent)

    refused = agent.tunnel_attempts[tried:]
    assert [a.status for a in refused] == [403, 403, 403]
    status = await agent.status()
    assert (status.connection_mode, status.poll_interval) == ("polling", 20)
    connections = https.connections
    sent = len(agent.requests)

    await agent.run(minutes=10)

    paths = [r.path for r in agent.requests[sent:]]
    assert paths.count("/agent/poll") == 30  # every 20 s
    assert {r.status for r in agent.requests[sent:]} == {200}
    assert https.connections == connections  # each poll reused it
    assert len(agent.tunnel_attempts) == tried + 3  # no tries meanwhile


async def test_a_polling_base_is_woken_for_a_remote_session_that_reaches_its_ui(
    portal: Portal, operator: Browser, agent: RunningAgent, server: int, ui: BaseUi
):
    base_id = (await agent.status()).base_id
    assert base_id
    await falls_back(agent)
    agent.upgrades_refused = False  # a tunnel may open again, when asked

    resp = await operator.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}, resp.text
    async with status_channel(server, operator, base_id) as bar:
        await bar.until("waking")
        await agent.run(seconds=20)  # the next poll carries the Wake
        await bar.until("connected")
    assert agent.tunnel_attempts[-1].status == 101

    stream = await portal.context.tunnels.open_stream(base_id)
    await stream.write(b"GET /survey HTTP/1.1\r\nHost: portal\r\n\r\n")
    data = b""
    while chunk := await asyncio.wait_for(stream.read(), 5):
        data += chunk
    assert data.endswith(b"base page /survey")
    assert [(s.method, s.path) for s in ui.seen] == [("GET", "/survey")]
    assert (await agent.status()).connection_mode == "polling"


async def test_a_polling_base_tries_its_tunnel_every_15_min_and_holds_it_once_it_opens(
    portal: Portal, agent: RunningAgent
):
    tried = await falls_back(agent)
    switched = agent.portal.clock.now()

    await agent.run(hours=1)

    retries = agent.tunnel_attempts[tried + 3 :]
    assert [a.status for a in retries] == [403] * 4
    times = [switched, *(a.at for a in retries)]
    gaps = [(b - a).total_seconds() for a, b in itertools.pairwise(times)]
    assert all(890 <= gap <= 920 for gap in gaps), gaps
    assert (await agent.status()).connection_mode == "polling"

    agent.upgrades_refused = False
    await agent.run(minutes=15)
    await mode(agent, "holding")
    base_id = (await agent.status()).base_id
    assert base_id and portal.context.tunnels.tunnel_up(base_id)
    polls = len([r for r in agent.requests if r.path == "/agent/poll"])
    await agent.run(minutes=5)
    assert len([r for r in agent.requests if r.path == "/agent/poll"]) == polls


async def test_with_its_https_failing_too_the_agent_keeps_backing_off_and_never_polls(
    agent: RunningAgent,
):
    agent.reachable = False
    tried = await drop(agent)

    for _ in range(12):
        await agent.run(minutes=5)
        assert (await agent.status()).connection_mode == "reconnecting"

    tries = agent.tunnel_attempts[tried:]
    assert all(a.status is None for a in tries)
    assert 5 <= len(tries) <= 30  # backing off, not every 20 s nor 15 min

    agent.reachable = True
    await agent.run(minutes=11)
    await mode(agent, "holding")


async def test_the_portal_logs_how_many_bases_are_in_each_mode(
    portal: Portal,
    operator: Browser,
    server: int,
    caplog: pytest.LogCaptureFixture,
):
    time = AgentTime(portal.clock)
    async with contextlib.AsyncExitStack() as stack:
        holding, polling, old = [
            await stack.enter_async_context(
                running_agent(
                    portal,
                    ip=f"198.51.100.{100 + i}",
                    server_port=server,
                    time=time,
                    protocol_version=1 if i == 2 else PROTOCOL_VERSION,
                )
            )
            for i in range(3)
        ]
        for i, a in enumerate((holding, polling, old)):
            await a.claim(operator, name=f"Base {i}")
        await mode(holding, "holding")
        await mode(polling, "holding")
        polling.upgrades_refused = True
        polling.drop_tunnel()
        for _ in range(60):
            await time.run(seconds=20)
            if (await polling.status()).connection_mode == "polling":
                break
        await mode(polling, "polling")

        caplog.clear()
        with caplog.at_level(logging.INFO, logger="sp_rtk_portal"):
            await eventually(
                lambda: (
                    "Bases by connection mode: 1 holding, 2 polling,"
                    " 0 reconnecting" in caplog.text
                ),
                "the Portal logs the counts",
            )
