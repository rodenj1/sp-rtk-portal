"""Seam 1: a holding base reconnects after its tunnel drops, spreading
itself out (ticket #206), and the Portal admits tunnel opens at a set rate.

After a drop the agent's first retry waits a random 0-60 s; each failure
after that doubles the window it picks from (full jitter), up to the
backoff cap from the agent config (~10 min). A 503 with ``Retry-After``
delays the next attempt by at least that long; a tunnel that opens resets
it all. The Portal admits ``tunnel_opens_per_second`` opens and answers the
rest 503 with a random 10-60 s ``Retry-After``, so a Portal restart doesn't
bring every base back at once.

The Portal is served over real TCP (websockets); the agents run on virtual
time; ``agent.tunnel_attempts`` records each tunnel open they tried.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import itertools
import statistics
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest
from sp_rtk_portal_protocol import PROTOCOL_VERSION, VERSION_HEADER, BaseKey
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import InvalidStatus

from .harness.agent import RunningAgent, TunnelAttempt, running_agent
from .harness.agent_time import AgentTime
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import ORIGIN, PORTAL_OWNER, Browser, Portal
from .harness.server import serving

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
async def agent(
    portal: Portal, operator: Browser, server: int
) -> AsyncIterator[RunningAgent]:
    async with running_agent(portal, server_port=server) as a:
        await a.claim(operator)
        await holding(portal, a)
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


async def holding(portal: Portal, agent: RunningAgent) -> None:
    """Wait until both ends see the base's tunnel held."""

    async def held() -> bool:
        status = await agent.status()
        return status.connection_mode == "holding" and bool(
            status.base_id and portal.context.tunnels.tunnel_up(status.base_id)
        )

    await eventually(held, "the base holds its tunnel")


@dataclass(frozen=True)
class Dropped:
    at: datetime
    """When the agent saw its tunnel go."""
    tried: int
    """How many tunnel opens it had tried by then."""


async def drop(agent: RunningAgent) -> Dropped:
    """The network drops the tunnel."""
    agent.drop_tunnel()

    async def closed() -> bool:
        return (await agent.status()).tunnel == "closed"

    await eventually(closed, "the agent sees its tunnel closed")
    return Dropped(agent.portal.clock.now(), len(agent.tunnel_attempts))


def attempts_since(agent: RunningAgent, dropped: Dropped) -> list[TunnelAttempt]:
    return agent.tunnel_attempts[dropped.tried :]


def gaps(dropped: Dropped, attempts: list[TunnelAttempt]) -> list[float]:
    """Seconds before each attempt: from the drop, then from the one before."""
    times = [dropped.at, *(a.at for a in attempts)]
    return [(b - a).total_seconds() for a, b in itertools.pairwise(times)]


async def set_config(owner: Browser, **values: object) -> None:
    resp = await owner.action("/settings/agent-config", values)
    assert resp.status_code == 200, resp.text


def admit(portal: Portal, per_second: int) -> None:
    portal.context.settings = dataclasses.replace(
        portal.context.settings, tunnel_opens_per_second=per_second
    )


# --- Backoff ------------------------------------------------------------------------


async def test_after_a_drop_the_first_retry_is_within_60_s_then_backs_off_to_the_cap(
    portal: Portal, agent: RunningAgent
):
    agent.reachable = False
    dropped = await drop(agent)

    await agent.run(hours=3)

    tries = attempts_since(agent, dropped)
    assert all(a.status is None for a in tries)  # none got through
    waits = gaps(dropped, tries)
    assert waits[0] <= 60
    # Each failure doubles the window the next wait is drawn from, up to
    # ~10 min: in 3 h far fewer tries than at the 20 s poll interval...
    for i, wait in enumerate(waits):
        assert wait <= min(600, 60 * 2**i), (i, waits)
    assert 15 <= len(tries) <= 120
    # ...and spread across the whole window, not bunched at its end.
    assert 150 <= statistics.mean(waits[5:]) <= 450, waits


async def test_a_tunnel_that_opens_resets_the_backoff(
    portal: Portal, agent: RunningAgent
):
    agent.reachable = False
    await drop(agent)
    await agent.run(hours=1)  # well into the backoff
    agent.reachable = True
    await agent.run(minutes=10)
    await holding(portal, agent)

    # Each drop now is retried within 60 s again (by chance from a 10 min
    # window, five in a row would be 1 in 100 000).
    for _ in range(5):
        dropped = await drop(agent)
        await agent.run(seconds=60)
        [retry] = attempts_since(agent, dropped)
        assert retry.status == 101
        await holding(portal, agent)


async def test_the_backoff_cap_comes_from_the_agent_config(
    portal: Portal, agent: RunningAgent, owner: Browser
):
    await set_config(owner, reconnect_backoff_cap="60")
    await agent.run(seconds=20)  # its next poll brings the new config
    assert (await agent.status()).config_revision == 2

    agent.reachable = False
    dropped = await drop(agent)
    await agent.run(hours=1)

    waits = gaps(dropped, attempts_since(agent, dropped))
    assert max(waits) <= 60
    assert len(waits) >= 60  # a 10 min cap would allow only a dozen or so


# --- Admission --------------------------------------------------------------------


async def test_a_503_with_retry_after_delays_the_next_attempt_at_least_that_long(
    portal: Portal, agent: RunningAgent, owner: Browser
):
    # A 1 min cap: without Retry-After most waits would be shorter than it.
    await set_config(owner, reconnect_backoff_cap="60")
    await agent.run(seconds=20)
    admit(portal, 0)  # the Portal admits no tunnel opens at all

    dropped = await drop(agent)
    await agent.run(minutes=30)

    tries = attempts_since(agent, dropped)
    assert len(tries) >= 15
    for attempt, wait in zip(tries, gaps(dropped, tries)[1:], strict=False):
        assert attempt.status == 503
        assert attempt.retry_after is not None
        assert 10 <= int(attempt.retry_after) <= 60
        assert wait >= int(attempt.retry_after)

    admit(portal, 100)
    await agent.run(minutes=2)
    await holding(portal, agent)


async def hand_open(portal: Portal, server: int, key: BaseKey) -> ClientConnection:
    """Open a tunnel by hand, as the base's agent would."""
    authorization = key.authorization(
        "GET", ORIGIN + "/agent/tunnel", now=portal.clock.now()
    )
    return await connect(
        f"ws://127.0.0.1:{server}/agent/tunnel",
        additional_headers={
            VERSION_HEADER: str(PROTOCOL_VERSION),
            "Authorization": authorization,
        },
    )


async def test_the_portal_admits_tunnel_opens_at_its_set_rate_and_answers_503_above(
    portal: Portal, agent: RunningAgent, server: int
):
    admit(portal, 3)
    portal.clock.advance(seconds=1)  # past the second the agent's own opened in

    opened = [await hand_open(portal, server, agent.key) for _ in range(3)]
    for _ in range(5):
        with pytest.raises(InvalidStatus) as refused:
            await hand_open(portal, server, agent.key)
        assert refused.value.response.status_code == 503
        assert 10 <= int(refused.value.response.headers["Retry-After"]) <= 60

    portal.clock.advance(seconds=1)  # the next second's opens
    opened.append(await hand_open(portal, server, agent.key))
    for ws in opened:
        await ws.close()


# --- A Portal restart -----------------------------------------------------------------


AGENTS = 20


async def test_after_a_portal_restart_bases_come_back_within_the_admission_rate(
    portal: Portal, operator: Browser, server: int
):
    # Every agent sleeps on one virtual time, so moving it wakes them all.
    time = AgentTime(portal.clock)
    async with contextlib.AsyncExitStack() as stack:
        agents = [
            await stack.enter_async_context(
                running_agent(
                    portal, ip=f"198.51.100.{100 + i}", server_port=server, time=time
                )
            )
            for i in range(AGENTS)
        ]
        for i, a in enumerate(agents):
            await a.claim(operator, name=f"Base {i}")
            await holding(portal, a)
        admit(portal, 1)  # a Portal made for a few bases at a time

        # The Portal restarts: every base's tunnel drops at once.
        dropped = [await drop(a) for a in agents]
        await time.run(minutes=10)

        for a in agents:
            await holding(portal, a)
        tries = sorted(
            (
                t
                for a, d in zip(agents, dropped, strict=True)
                for t in attempts_since(a, d)
            ),
            key=lambda t: t.at,
        )
        opens = [t.at for t in tries if t.status == 101]
        assert len(opens) == AGENTS  # each came back once, and stayed
        for at in opens:  # never more than one in any second
            assert [o for o in opens if at - timedelta(seconds=1) < o <= at] == [at]
        turned_away = [t for t in tries if t.status != 101]
        assert turned_away  # the rest were told to come back later...
        assert {t.status for t in turned_away} == {503}
        assert opens[-1] - dropped[0].at <= timedelta(minutes=10)  # ...and did
