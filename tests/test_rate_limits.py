"""Seam 1: rate limits (ticket #98).

- A poll or Check-in faster than half its interval gets 429, and the real
  agent backs off.
- Claim starts: 10 an hour per public IP.
- Wrong approve codes: 10 an hour per account, plus a global cap.
- Shares: a cap per Operator an hour (each one emails someone).

Every limit is read from ``Settings`` at the moment it applies; tests change
them with ``_limits(portal, ...)``. Counters live in the Portal process.
"""

from __future__ import annotations

import dataclasses
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from sp_rtk_portal_protocol import CHECK_IN_PATH, POLL_PATH, BaseKey

from .harness.agent import RunningAgent, running_agent
from .harness.fake_authentik import FakeAuthentik
from .harness.fake_smtp import FakeSmtp
from .harness.pages import base_card
from .harness.portal import Browser, Portal
from .harness.signer import SigningAgent, signing_agent

EMAIL = "operator@example.com"
OTHER = "other@example.com"
PASSWORD = "correct horse battery staple"
STRANGER = "198.18.0.5"


def _limits(portal: Portal, **values: Any) -> None:
    ctx = portal.context
    ctx.settings = dataclasses.replace(ctx.settings, **values)


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
async def other(portal: Portal, authentik: FakeAuthentik) -> AsyncIterator[Browser]:
    authentik.add_user(OTHER, PASSWORD)
    async with portal.browser(ip="203.0.113.50") as b:
        assert (await b.sign_in(OTHER, PASSWORD)).json() == {"next": "/"}
        yield b


async def _start(agent: SigningAgent) -> Any:
    """A Claim start, each with a new key (as a new install would)."""
    return await agent.post("/agent/claims", {"name": "pi"}, key=BaseKey.generate())


# --- Claim starts -------------------------------------------------------------


async def test_the_11th_claim_start_from_one_ip_in_an_hour_is_refused(
    portal: Portal,
):
    async with signing_agent(portal, ip="198.51.100.20") as agent:
        for _ in range(10):
            assert (await _start(agent)).status_code == 200

        refused = await _start(agent)

        assert refused.status_code == 429
        assert refused.json()["error"] == "slow_down"
        assert 0 < int(refused.headers["retry-after"]) <= 3600
        async with signing_agent(portal, ip="198.51.100.21") as elsewhere:
            assert (await _start(elsewhere)).status_code == 200

        portal.clock.advance(minutes=60)
        assert (await _start(agent)).status_code == 200


async def test_untrusted_claim_starts_share_one_limit_whatever_ip_they_claim(
    portal: Portal,
):
    for n in range(10):
        async with signing_agent(portal, ip=f"192.0.2.{n}", peer=STRANGER) as a:
            assert (await _start(a)).status_code == 200

    async with signing_agent(portal, ip="192.0.2.200", peer=STRANGER) as a:
        assert (await _start(a)).status_code == 429


async def test_the_claim_start_limit_is_configurable(portal: Portal):
    _limits(portal, claim_starts_per_ip=2)
    async with signing_agent(portal) as agent:
        assert (await _start(agent)).status_code == 200
        assert (await _start(agent)).status_code == 200
        assert (await _start(agent)).status_code == 429


async def test_the_real_agent_says_too_many_claims_started_from_its_network(
    portal: Portal,
):
    _limits(portal, claim_starts_per_ip=0)
    async with running_agent(portal) as agent:
        with pytest.raises(Exception, match="Too many Claims") as refused:
            await agent.connect()

        assert "Try again in 60 minutes" in str(refused.value)
        assert (await agent.status()).state == "not_connected"


# --- Wrong approve codes --------------------------------------------------------

TOO_MANY = "Too many wrong codes. Try again in"


async def _approve(browser: Browser, code: str) -> Any:
    return await browser.action("/claim", {"code": code, "name": "North"})


async def test_the_11th_wrong_code_on_one_account_in_an_hour_is_refused(
    portal: Portal, operator: Browser, other: Browser
):
    for _ in range(10):
        assert (await _approve(operator, "BBBBBBBB")).status_code == 400
    async with signing_agent(portal) as agent:
        right = (await _start(agent)).json()["user_code"]

    refused = await _approve(operator, right)  # even a right code, now

    assert refused.status_code == 429
    assert refused.json()["error"].startswith(TOO_MANY)
    assert await portal.query("SELECT * FROM base") == []
    # Another account is not held back by this one's guesses.
    assert (await _approve(other, right)).json() == {"next": "/"}


async def test_wrong_codes_are_allowed_again_an_hour_later(
    portal: Portal, operator: Browser
):
    for _ in range(10):
        await _approve(operator, "BBBBBBBB")
    portal.clock.advance(minutes=60)

    resp = await _approve(operator, "BBBBBBBB")

    assert resp.status_code == 400
    assert "No base is waiting" in resp.json()["error"]


async def test_wrong_codes_on_the_claim_page_count_and_are_refused_too(
    portal: Portal, operator: Browser
):
    for _ in range(10):
        page = await operator.get("/claim?code=BBBBBBBB")
        assert "No base is waiting" in page.text
    async with signing_agent(portal) as agent:
        right = (await _start(agent)).json()["user_code"]

    page = await operator.get(f"/claim?code={right}")

    assert TOO_MANY in page.text
    assert 'class="pending"' not in page.text  # nothing about the pairing
    assert (await _approve(operator, right)).status_code == 429


async def test_wrong_codes_have_a_global_cap_across_accounts(
    portal: Portal, operator: Browser, other: Browser
):
    _limits(portal, wrong_codes_overall=3)
    await _approve(operator, "BBBBBBBB")
    await _approve(operator, "CCCCCCCC")
    await _approve(other, "DDDDDDDD")

    refused = await _approve(other, "FFFFFFFF")

    assert refused.status_code == 429
    assert refused.json()["error"].startswith(TOO_MANY)


async def test_the_wrong_code_limit_per_account_is_configurable(
    portal: Portal, operator: Browser
):
    _limits(portal, wrong_codes_per_account=1)
    assert (await _approve(operator, "BBBBBBBB")).status_code == 400
    assert (await _approve(operator, "BBBBBBBB")).status_code == 429


# --- Polls and Check-ins --------------------------------------------------------


@asynccontextmanager
async def _claimed(portal: Portal, operator: Browser) -> AsyncIterator[RunningAgent]:
    """A Claimed base whose agent has Checked in and polled once (just now)."""
    async with running_agent(portal) as agent:
        await agent.claim(operator)
        yield agent


async def _poll(portal: Portal, agent: RunningAgent, ip: str | None = None) -> Any:
    """A poll signed with the base's own key, sent by hand."""
    async with signing_agent(portal, ip=ip or agent.ip) as hand:
        return await hand.post(POLL_PATH, {"state": "connected"}, key=agent.key)


async def _check_in(portal: Portal, agent: RunningAgent) -> Any:
    async with signing_agent(portal, ip=agent.ip) as hand:
        return await hand.post(CHECK_IN_PATH, {}, key=agent.key)


async def test_a_poll_sooner_than_half_its_interval_gets_429(
    portal: Portal, operator: Browser
):
    _limits(portal, agent_burst=1)
    async with _claimed(portal, operator) as agent:
        portal.clock.advance(seconds=9)  # half of 20 s is 10 s

        refused = await _poll(portal, agent)

        assert refused.status_code == 429
        assert refused.json()["error"] == "slow_down"
        assert refused.headers["retry-after"] == "1"
        portal.clock.advance(seconds=1)
        assert (await _poll(portal, agent)).status_code == 200


async def test_a_check_in_sooner_than_half_its_interval_gets_429(
    portal: Portal, operator: Browser
):
    _limits(portal, agent_burst=1)
    async with _claimed(portal, operator) as agent:
        portal.clock.advance(seconds=149)  # half of 5 min is 150 s

        refused = await _check_in(portal, agent)

        assert refused.status_code == 429
        assert refused.headers["retry-after"] == "1"
        portal.clock.advance(seconds=1)
        assert (await _check_in(portal, agent)).status_code == 200


async def test_a_metered_base_is_held_to_half_of_60_s(
    portal: Portal, operator: Browser
):
    _limits(portal, agent_burst=1)
    async with _claimed(portal, operator) as agent:
        base_id = (await agent.status()).base_id
        await operator.action(f"/bases/{base_id}/metered", {"metered": "true"})
        await agent.run(seconds=20)  # this poll tells it: metered
        portal.clock.advance(seconds=29)

        assert (await _poll(portal, agent)).status_code == 429
        portal.clock.advance(seconds=1)
        assert (await _poll(portal, agent)).status_code == 200


async def test_a_few_early_polls_pass_before_the_limit_bites(
    portal: Portal, operator: Browser
):
    async with _claimed(portal, operator) as agent:
        # The agent's own poll used one of 3; a restart, a resumed pause or
        # a Doorbell change may each bring one forward.
        assert (await _poll(portal, agent)).status_code == 200
        assert (await _poll(portal, agent)).status_code == 200

        assert (await _poll(portal, agent)).status_code == 429


async def test_the_real_agent_backs_off_when_told_and_stays_online(
    portal: Portal, operator: Browser
):
    # Its 20 s polls are now "too fast": no closer than 30 s, no burst.
    _limits(portal, agent_min_spacing=1.5, agent_burst=1)
    async with _claimed(portal, operator) as agent:
        await agent.run(minutes=5)

        polls = [r for r in agent.requests if r.path == POLL_PATH]
        refused = [p for p in polls if p.status == 429]
        assert refused, polls
        for slow_down in refused:
            after = polls[polls.index(slow_down) + 1]
            # It waited at least twice its interval, and was served.
            assert (after.at - slow_down.at).total_seconds() >= 40
            assert after.status == 200
        status = await agent.status()
        assert status.state == "connected"
        page = await operator.get("/")
        assert base_card(page.text, status.base_id)["state"] == ["Online"]


# --- Shares ---------------------------------------------------------------------


async def test_shares_per_operator_are_limited_an_hour(
    portal: Portal, operator: Browser, smtp: FakeSmtp
):
    _limits(portal, shares_per_operator=2)
    async with _claimed(portal, operator) as agent:
        base_id = (await agent.status()).base_id
        path = f"/bases/{base_id}/shares"
        for n in range(2):
            ok = await operator.action(path, {"email": f"c{n}@example.com"})
            assert ok.status_code == 200, ok.text
        sent = len(smtp.outbox)

        refused = await operator.action(path, {"email": "c9@example.com"})

        assert refused.status_code == 429
        assert refused.json()["error"].startswith("Too many Shares. Try again in")
        assert len(smtp.outbox) == sent  # nobody emailed
        portal.clock.advance(minutes=60)
        again = await operator.action(path, {"email": "c9@example.com"})
        assert again.status_code == 200, again.text
