"""Seam 1: the Doorbell (ticket #100, ADR 0002).

The real agent sends keepalives over real UDP to a stub Doorbell server,
which relays them to the Portal's Doorbell interface; a Wake goes back as a
ring down the same path and the agent opens its tunnel at once, without
waiting for a poll. The real Doorbell server isn't deployed in v1.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timedelta

import httpx
import pytest
from sp_rtk_portal_protocol import BaseKey, HeardKeepalive, KeepalivesReport, doorbell

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.doorbell_server import (
    BELL_ADDRESS,
    BELL_HOST,
    DOORBELL_TOKEN,
    StubDoorbell,
    stub_doorbell,
    wire,
)
from .harness.fake_authentik import FakeAuthentik
from .harness.pages import base_card
from .harness.portal import PORTAL_OWNER, Browser, Portal
from .harness.server import serving

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"
TUNNEL_URL = "wss://sp-rtk-base.big-spray.com/agent/tunnel"


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
async def owner(portal: Portal, authentik: FakeAuthentik) -> AsyncIterator[Browser]:
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
async def bell(portal: Portal) -> AsyncIterator[StubDoorbell]:
    async with stub_doorbell(portal.app, portal.origin) as stub:
        yield stub


@pytest.fixture
async def agent(
    portal: Portal, operator: Browser, server: int, ui: BaseUi, bell: StubDoorbell
) -> AsyncIterator[RunningAgent]:
    async with running_agent(portal, server_port=server, app_port=ui.port) as a:
        await a.claim(operator)
        wire(a, bell)
        yield a


async def _card(operator: Browser, agent: RunningAgent) -> dict[str, list[str]]:
    base_id = (await agent.status()).base_id
    assert base_id
    page = await operator.get("/")
    return base_card(page.text, base_id)


async def _name_the_bell(owner: Browser, host: str = BELL_HOST) -> None:
    resp = await owner.action(
        "/settings/agent-config",
        {"doorbell_host": host, "doorbell_port": str(BELL_ADDRESS[1])},
    )
    assert resp.status_code == 200, resp.text


async def _on_the_doorbell(agent: RunningAgent, owner: Browser) -> None:
    """The Portal owner names the Doorbell; the base moves onto it."""
    await _name_the_bell(owner)
    await agent.run(minutes=6)
    status = await agent.status()
    assert (status.doorbell, status.wake_mode) == ("ok", "doorbell"), status


async def eventually(check: Callable[[], Awaitable[bool]], what: str) -> None:
    for _ in range(500):
        if await check():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"never: {what}")


# --- Keepalives and Doorbell mode -------------------------------------------------


async def test_with_a_doorbell_host_the_base_sends_keepalives_and_goes_on_the_doorbell(
    portal: Portal,
    agent: RunningAgent,
    owner: Browser,
    operator: Browser,
    bell: StubDoorbell,
):
    await _on_the_doorbell(agent, owner)

    assert len(bell.received) >= 10
    assert set(bell.results) == {"ok"}
    card = await _card(operator, agent)
    assert card["state"] == ["Online"]
    assert card["wake-mode"] == ["Doorbell"]
    assert card["doorbell"] == ["Doorbell: ok"]

    # It no longer polls: only keepalives and the odd Check-in.
    requests = agent.traffic.requests
    await agent.run(minutes=10)
    assert agent.traffic.requests - requests <= 3
    assert (await _card(operator, agent))["state"] == ["Online"]


async def test_a_ring_opens_the_tunnel_within_seconds_without_a_poll(
    portal: Portal,
    agent: RunningAgent,
    owner: Browser,
    operator: Browser,
    bell: StubDoorbell,
):
    await _on_the_doorbell(agent, owner)
    base_id = (await agent.status()).base_id
    requests = agent.traffic.requests

    resp = await operator.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}, resp.text

    async def tunnel_open() -> bool:
        return (await agent.status()).tunnel == "open"

    started = asyncio.get_running_loop().time()
    await eventually(tunnel_open, "the tunnel opened")  # virtual time stands still
    assert asyncio.get_running_loop().time() - started < 3
    assert agent.traffic.requests == requests  # no poll carried the Wake
    assert len(bell.rung) >= 1
    assert agent.tunnel_urls == [TUNNEL_URL]
    assert portal.context.tunnels.tunnel_up(base_id)


async def test_a_ring_still_needs_the_signed_nonce_echo(
    portal: Portal,
    agent: RunningAgent,
    owner: Browser,
    bell: StubDoorbell,
):
    await _on_the_doorbell(agent, owner)
    base_id = (await agent.status()).base_id
    [row] = await portal.query("SELECT ring_key FROM base WHERE id = %s", base_id)
    agent_source = bell.received[-1][1]

    # A ring that is genuine in every way but carries a nonce the Portal never
    # issued (a leaked ring key, say): the agent tries, the Portal refuses.
    forged = doorbell.ring(row["ring_key"], "not-a-wake", now=portal.clock.now())
    bell.send(forged, agent_source)

    async def tried() -> bool:
        return len(agent.tunnel_urls) == 1 and (await agent.status()).tunnel == "closed"

    await eventually(tried, "the agent tried to open its tunnel")
    await asyncio.sleep(0.1)
    assert not portal.context.tunnels.tunnel_up(base_id)


async def test_without_a_doorbell_host_the_agent_sends_no_udp(
    agent: RunningAgent, operator: Browser, bell: StubDoorbell
):
    await agent.run(minutes=10)

    assert agent.udp.sent == [] and bell.arrived == 0
    card = await _card(operator, agent)
    assert card["wake-mode"] == ["Polling every 20 s"]
    assert card["doorbell"] == ["Doorbell: off"]


async def test_a_doorbell_host_resolving_to_a_private_address_gets_no_udp(
    agent: RunningAgent,
    owner: Browser,
    operator: Browser,
    bell: StubDoorbell,
    caplog: pytest.LogCaptureFixture,
):
    agent.dns.records[BELL_HOST] = ["10.0.0.7"]
    with caplog.at_level(logging.WARNING):
        await _name_the_bell(owner)
        await agent.run(minutes=6)

    assert agent.udp.sent == [] and bell.arrived == 0
    assert BELL_HOST in caplog.text and "10.0.0.7" in caplog.text
    card = await _card(operator, agent)
    assert card["wake-mode"] == ["Polling every 20 s"]
    assert card["doorbell"] == ["Doorbell: ignored"]
    assert (await agent.status()).doorbell == "ignored"


# --- Online state -------------------------------------------------------------------


async def test_a_doorbell_base_goes_offline_after_3_missed_keepalives(
    portal: Portal,
    agent: RunningAgent,
    owner: Browser,
    operator: Browser,
    bell: StubDoorbell,
):
    await _on_the_doorbell(agent, owner)
    # Just after a Check-in, so the next one is 5 min away.
    [before] = await portal.query("SELECT last_check_in_at FROM base")
    while True:
        await agent.time.step()
        [now] = await portal.query("SELECT last_check_in_at FROM base")
        if now != before:
            break
    bell.deaf = True  # the Doorbell server goes down
    [row] = await portal.query("SELECT last_seen_at FROM base")
    last: datetime = row["last_seen_at"]

    # 3 keepalive beats (20 s + up to 5 s jitter) = 75 s: a polling base
    # would be offline after 60 s.
    await agent.time.run(last + timedelta(seconds=74) - portal.clock.now())
    assert (await _card(operator, agent))["state"] == ["Online"]
    await agent.time.run(timedelta(seconds=2))
    assert (await _card(operator, agent))["state"] == ["Offline"]


async def test_back_on_polling_when_the_portal_stops_hearing_the_doorbell(
    agent: RunningAgent, owner: Browser, operator: Browser, bell: StubDoorbell
):
    await _on_the_doorbell(agent, owner)
    bell.deaf = True

    await agent.run(minutes=6)

    status = await agent.status()
    assert (status.doorbell, status.wake_mode) == ("unavailable", "polling")
    card = await _card(operator, agent)
    assert card["state"] == ["Online"]
    assert card["wake-mode"] == ["Polling every 20 s"]


# --- The Doorbell server's HTTPS interface ---------------------------------------------


@pytest.fixture
async def doorbell_http(portal: Portal) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=portal.app), base_url=portal.origin
    ) as http:
        yield http


def _report(packet: bytes) -> dict[str, object]:
    return KeepalivesReport(
        keepalives=[
            HeardKeepalive(
                packet=doorbell.encode_packet(packet), address="198.51.100.30", port=1
            )
        ]
    ).to_json()


@pytest.mark.parametrize("token", [None, "wrong"])
async def test_the_doorbell_interface_needs_the_doorbell_token(
    doorbell_http: httpx.AsyncClient, portal: Portal, token: str | None
):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    packet = doorbell.keepalive(BaseKey.generate(), now=portal.clock.now())

    posted = await doorbell_http.post(
        doorbell.KEEPALIVES_PATH, json=_report(packet), headers=headers
    )
    rings = await doorbell_http.get(doorbell.RINGS_PATH, headers=headers)

    assert (posted.status_code, rings.status_code) == (401, 401)


async def test_the_doorbell_interface_is_off_without_a_token(
    doorbell_http: httpx.AsyncClient, portal: Portal
):
    portal.context.settings = dataclasses.replace(
        portal.context.settings, doorbell_token=""
    )
    headers = {"Authorization": "Bearer "}

    posted = await doorbell_http.post(
        doorbell.KEEPALIVES_PATH, json={"keepalives": []}, headers=headers
    )
    rings = await doorbell_http.get(doorbell.RINGS_PATH, headers=headers)

    assert (posted.status_code, rings.status_code) == (404, 404)


async def test_keepalives_the_portal_cant_trust_are_refused(
    portal: Portal,
    agent: RunningAgent,
    doorbell_http: httpx.AsyncClient,
):
    now = portal.clock.now()
    genuine = doorbell.keepalive(agent.key, now=now)
    stale = doorbell.keepalive(agent.key, now=now - timedelta(minutes=5))
    stranger = doorbell.keepalive(BaseKey.generate(), now=now)
    headers = {"Authorization": f"Bearer {DOORBELL_TOKEN}"}

    results = []
    for packet in (genuine, genuine, stale, stranger, b"garbage"):
        resp = await doorbell_http.post(
            doorbell.KEEPALIVES_PATH, json=_report(packet), headers=headers
        )
        assert resp.status_code == 200, resp.text
        results += resp.json()["results"]

    # The second copy of the same keepalive is a replay.
    assert results == ["ok", "invalid", "invalid", "unknown", "invalid"]
