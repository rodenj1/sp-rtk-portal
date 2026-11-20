"""Seam 1: a Claimed base's polls and Check-ins reuse one HTTPS connection
to the Portal (ticket #201), so a poll costs its request and response, not
a new TCP connection and TLS handshake.

The agent's HTTPS runs over a real wire (:mod:`.harness.wire`) that counts
the connections it opens; the agent runs on virtual time.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest

from .harness.agent import RunningAgent, running_agent
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser, Portal
from .harness.wire import Wire, wire

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


@dataclass
class Wired:
    agent: RunningAgent
    wire: Wire


@pytest.fixture
async def base(portal: Portal, operator: Browser) -> AsyncIterator[Wired]:
    """A Claimed polling base (protocol version 1; a version 2 one polls
    only once it fell back, see ``test_fallback``) whose agent has Checked in
    and polled once, over the wire."""
    async with (
        wire(portal) as w,
        running_agent(portal, transport=w.transport, protocol_version=1) as a,
    ):
        await a.claim(operator)
        yield Wired(a, w)


async def test_polls_and_check_ins_reuse_one_connection(base: Wired):
    connections = base.wire.connections
    sent = len(base.agent.requests)

    await base.agent.run(hours=1)

    paths = [r.path for r in base.agent.requests[sent:]]
    assert paths.count("/agent/poll") == 180
    assert paths.count("/agent/check-in") == 12
    assert {r.status for r in base.agent.requests[sent:]} == {200}
    assert base.wire.connections == connections


async def test_after_the_portal_closes_the_idle_connection_the_next_poll_reconnects(
    base: Wired,
):
    await base.agent.run(seconds=20)
    before = list(base.agent.requests)

    await base.wire.close()
    await base.agent.run(seconds=20)

    [poll] = base.agent.requests[len(before) :]
    assert poll.path == "/agent/poll"
    assert poll.status == 200
    assert (poll.at - before[-1].at).total_seconds() == 20  # no missed beat
    assert base.wire.connections == 2
    assert (await base.agent.status()).message is None


async def test_a_reused_connection_costs_a_fraction_of_a_new_one(base: Wired):
    """Bytes per poll at the wire: TLS records (and handshakes) both ways."""
    w = base.wire
    await base.agent.run(seconds=20)
    w.sent = w.received = 0

    await base.agent.run(seconds=20)
    reused = w.sent + w.received

    await w.close()
    w.sent = w.received = 0
    await base.agent.run(seconds=20)
    fresh = w.sent + w.received

    print(f"\nbytes per poll: {fresh} B on a new connection, {reused} B reused")
    assert reused < fresh / 2
