"""Seam 1: possible copy (ticket #98).

The same base key polling from two public IPs, interleaved within 5 minutes
(A, B, A), flags the base "possible copy" in its Operator's list and emails
the Operator once. Nothing is blocked: both copies' polls are still served.
A base that simply moves (A, then B for good) is not flagged.

The real agent polls from ``agent.ip``; the "copy" is the same key used by
hand (a cloned SD card) from elsewhere.
"""

from __future__ import annotations

import dataclasses
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sp_rtk_portal_protocol import (
    CHECK_IN_PATH,
    POLL_PATH,
    HeardKeepalive,
    KeepalivesReport,
    doorbell,
)

from .harness.agent import RunningAgent, running_agent
from .harness.doorbell_server import DOORBELL_TOKEN
from .harness.fake_authentik import FakeAuthentik
from .harness.fake_smtp import FakeSmtp
from .harness.pages import base_card
from .harness.portal import Browser, Portal
from .harness.signer import signing_agent

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"
COPY_IP = "203.0.113.200"
STRANGER = "198.18.0.5"


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
async def agent(portal: Portal, operator: Browser) -> AsyncIterator[RunningAgent]:
    async with running_agent(portal) as a:
        await a.claim(operator)
        yield a


async def _copy(
    portal: Portal,
    agent: RunningAgent,
    path: str = POLL_PATH,
    ip: str | None = COPY_IP,
    **kwargs: Any,
) -> Any:
    """The cloned card's request: the same key, from ``ip``."""
    body = {"state": "connected"} if path == POLL_PATH else {}
    async with signing_agent(portal, ip=ip, **kwargs) as copy:
        resp = await copy.post(path, body, key=agent.key)
    assert resp.status_code == 200, resp.text
    return resp


async def _card(operator: Browser, agent: RunningAgent) -> dict[str, list[str]]:
    base_id = (await agent.status()).base_id
    assert base_id
    return base_card((await operator.get("/")).text, base_id)


async def test_interleaved_polls_from_two_ips_flag_a_possible_copy(
    portal: Portal, operator: Browser, agent: RunningAgent, smtp: FakeSmtp
):
    assert "possible-copy" not in await _card(operator, agent)
    portal.clock.advance(seconds=5)
    await _copy(portal, agent)  # A (the agent), then B (the copy)...
    await agent.run(seconds=20)  # ...then A again: interleaved

    card = await _card(operator, agent)
    [flag] = card["possible-copy"]
    assert "Possible copy" in flag
    assert agent.ip in flag and COPY_IP in flag
    [mail] = smtp.to(EMAIL)
    assert "possible copy" in mail.subject.lower()
    assert "North field" in mail.subject
    assert agent.ip in mail.body and COPY_IP in mail.body
    # Nothing is blocked: both go on being served.
    await _copy(portal, agent)
    await agent.run(seconds=20)
    assert (await agent.status()).state == "connected"
    assert agent.requests[-1].status == 200


async def test_the_operator_is_emailed_once(
    portal: Portal, operator: Browser, agent: RunningAgent, smtp: FakeSmtp
):
    for _ in range(4):
        portal.clock.advance(seconds=5)
        await _copy(portal, agent)
        await agent.run(seconds=20)

    assert len(smtp.to(EMAIL)) == 1


async def test_check_ins_count_too(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    portal.clock.advance(seconds=5)
    await _copy(portal, agent, CHECK_IN_PATH)
    await agent.run(seconds=20)

    assert "possible-copy" in await _card(operator, agent)


async def test_a_base_that_moves_to_a_new_ip_is_not_a_copy(
    portal: Portal, operator: Browser, agent: RunningAgent, smtp: FakeSmtp
):
    await agent.run(seconds=40)
    agent.ip = COPY_IP  # e.g. its ISP gave it a new address
    await agent.run(minutes=10)

    assert "possible-copy" not in await _card(operator, agent)
    assert smtp.to(EMAIL) == []


async def test_polls_from_two_ips_more_than_5_minutes_apart_are_not_a_copy(
    portal: Portal, operator: Browser, agent: RunningAgent, smtp: FakeSmtp
):
    agent.reachable = False  # the base is off for a while...
    await agent.run(seconds=60)
    await _copy(portal, agent)  # ...used elsewhere once...
    await agent.run(minutes=5, seconds=1)
    agent.reachable = True  # ...and back home more than 5 min later
    await agent.run(seconds=20)

    assert "possible-copy" not in await _card(operator, agent)


async def test_the_window_is_configurable(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    ctx = portal.context
    ctx.settings = dataclasses.replace(
        ctx.settings, possible_copy_window=timedelta(seconds=10)
    )
    portal.clock.advance(seconds=5)
    await _copy(portal, agent)
    await agent.run(seconds=20)  # 15 s after the copy's poll

    assert "possible-copy" not in await _card(operator, agent)


async def test_requests_without_a_trusted_ip_are_never_a_copy(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    portal.clock.advance(seconds=5)
    await _copy(portal, agent, ip=COPY_IP, peer=STRANGER)
    await agent.run(seconds=20)
    portal.clock.advance(seconds=5)
    await _copy(portal, agent, ip=None)
    await agent.run(seconds=20)

    assert "possible-copy" not in await _card(operator, agent)


async def test_a_possible_copy_is_audited(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    portal.clock.advance(seconds=5)
    await _copy(portal, agent)
    await agent.run(seconds=20)

    [entry] = await portal.query(
        "SELECT base_id, host(ip) AS ip, detail FROM audit_entry"
        " WHERE kind = 'possible_copy'"
    )
    assert entry["base_id"] == (await agent.status()).base_id
    assert entry["ip"] == agent.ip
    assert entry["detail"] == {"ips": [COPY_IP, agent.ip]}


async def test_doorbell_keepalives_count_too(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    # A copy on the Doorbell polls no more: its keepalives give its address.
    portal.clock.advance(seconds=5)
    packet = doorbell.keepalive(agent.key, now=portal.clock.now())
    report = KeepalivesReport(
        keepalives=[
            HeardKeepalive(
                packet=doorbell.encode_packet(packet), address=COPY_IP, port=40000
            )
        ]
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=portal.app), base_url=portal.origin
    ) as http:
        resp = await http.post(
            doorbell.KEEPALIVES_PATH,
            json=report.to_json(),
            headers={"Authorization": f"Bearer {DOORBELL_TOKEN}"},
        )
    assert resp.json()["results"] == ["ok"]
    await agent.run(seconds=20)

    [flag] = (await _card(operator, agent))["possible-copy"]
    assert COPY_IP in flag


async def test_a_dual_stack_base_switching_between_ipv4_and_ipv6_is_not_a_copy(
    portal: Portal, operator: Browser, agent: RunningAgent, smtp: FakeSmtp
):
    for _ in range(3):
        portal.clock.advance(seconds=5)
        await _copy(portal, agent, ip="2001:db8:5:6::1")  # the same base, on v6
        await agent.run(seconds=20)

    assert "possible-copy" not in await _card(operator, agent)


async def test_ipv6_addresses_in_one_64_are_one_place(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    agent.ip = "2001:db8:5:6::1"
    await agent.run(seconds=20)
    portal.clock.advance(seconds=5)
    await _copy(portal, agent, ip="2001:db8:5:6:a8f3::9")  # a privacy address
    await agent.run(seconds=20)
    assert "possible-copy" not in await _card(operator, agent)

    portal.clock.advance(seconds=5)
    await _copy(portal, agent, ip="2001:db8:7:8::1")  # another network
    await agent.run(seconds=20)
    [flag] = (await _card(operator, agent))["possible-copy"]
    assert "2001:db8:7:8::1" in flag
