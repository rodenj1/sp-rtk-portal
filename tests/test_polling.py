"""Seam 1: a Claimed base polls and Checks in; the Portal shows it online or
offline, with what its Check-ins report, and steers it with the agent
config (ticket #87, ADR 0002).

The real agent runs on virtual time: ``agent.run(seconds=...)`` lets time
pass and the agent polls exactly when it would.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from collections.abc import AsyncIterator
from datetime import datetime, timedelta

import pytest
from sp_rtk_base import __version__ as base_version
from sp_rtk_portal_protocol import PROTOCOL_VERSION

from .harness.agent import RunningAgent, running_agent
from .harness.fake_authentik import FakeAuthentik
from .harness.pages import base_card, fields
from .harness.portal import PORTAL_OWNER, Browser, Portal
from .harness.signer import signing_agent

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
async def agent(portal: Portal, operator: Browser) -> AsyncIterator[RunningAgent]:
    """A Claimed base whose agent has Checked in and polled once."""
    async with running_agent(portal) as a:
        await a.claim(operator)
        yield a


async def _card(operator: Browser, agent: RunningAgent) -> dict[str, list[str]]:
    base_id = (await agent.status()).base_id
    assert base_id
    page = await operator.get("/")
    assert page.status_code == 200
    return base_card(page.text, base_id)


def _seen(card: dict[str, list[str]]) -> datetime:
    return datetime.fromisoformat(card["last-seen@datetime"][0])


async def _config(owner: Browser, **values: object) -> None:
    resp = await owner.action("/settings/agent-config", values)
    assert resp.status_code == 200, resp.text


# --- Online state ---------------------------------------------------------------


async def test_a_polling_base_is_online_and_offline_after_3_missed_polls(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    await agent.run(minutes=2)
    card = await _card(operator, agent)
    assert card["state"] == ["Online"]
    assert _seen(card) == portal.clock.now() - timedelta(seconds=0)
    last_poll = portal.clock.now()

    agent.reachable = False  # the base loses its internet connection
    await agent.run(seconds=60)
    assert (await _card(operator, agent))["state"] == ["Online"]
    await agent.run(seconds=1)

    card = await _card(operator, agent)
    assert card["state"] == ["Offline"]
    assert _seen(card) == last_poll


async def test_a_base_comes_back_online_with_its_next_poll(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    agent.reachable = False
    await agent.run(minutes=10)
    assert (await _card(operator, agent))["state"] == ["Offline"]

    agent.reachable = True
    await agent.run(seconds=20)

    card = await _card(operator, agent)
    assert card["state"] == ["Online"]
    assert _seen(card) == portal.clock.now()


async def test_metered_switches_the_poll_interval_and_the_offline_threshold(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    base_id = (await agent.status()).base_id
    resp = await operator.action(f"/bases/{base_id}/metered", {"metered": "true"})
    assert resp.status_code == 200, resp.text
    await agent.run(seconds=20)  # this poll learns it

    status = await agent.status()
    assert status.metered
    assert status.poll_interval == 60
    card = await _card(operator, agent)
    assert card["wake-mode"] == ["Polling every 60 s (metered)"]

    await agent.run(seconds=60)
    last_poll = _seen(await _card(operator, agent))
    assert last_poll == portal.clock.now()
    await agent.run(seconds=59)
    assert _seen(await _card(operator, agent)) == last_poll  # no poll in between

    agent.reachable = False
    await agent.run(seconds=180 - 59)
    assert (await _card(operator, agent))["state"] == ["Online"]
    await agent.run(seconds=1)
    assert (await _card(operator, agent))["state"] == ["Offline"]


async def test_unmarking_metered_goes_back_to_20_s(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    base_id = (await agent.status()).base_id
    await operator.action(f"/bases/{base_id}/metered", {"metered": "true"})
    await agent.run(seconds=20)

    resp = await operator.action(f"/bases/{base_id}/metered", {"metered": "false"})
    assert resp.status_code == 200
    # Polled while metered: the base may not poll again for 60 s, and isn't
    # shown offline meanwhile.
    agent.reachable = False
    await agent.run(seconds=179)
    assert (await _card(operator, agent))["state"] == ["Online"]
    agent.reachable = True
    await agent.run(seconds=60)

    assert (await agent.status()).poll_interval == 20


# --- Check-ins ----------------------------------------------------------------------


async def test_check_in_data_and_the_public_ip_show_on_the_base(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    card = await _card(operator, agent)

    assert card["version"] == [f"sp-rtk-base {base_version}"]
    assert card["lan"] == ["192.168.1.20 (eth0, primary)", "10.8.0.4 (wlan0)"]
    assert card["public-ip"] == [agent.ip]
    assert card["wake-mode"] == ["Polling every 20 s"]
    assert card["doorbell"] == ["Doorbell: off"]
    assert card["protocol"] == [f"Protocol {PROTOCOL_VERSION}"]


async def test_a_later_check_in_updates_the_lan_addresses_and_public_ip(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    agent.lan = []
    agent.ip = "198.51.100.99"
    await agent.run(minutes=5)

    card = await _card(operator, agent)
    assert "lan" not in card
    assert card["public-ip"] == ["198.51.100.99"]


async def test_the_local_page_shows_last_contact_and_wake_mode(
    portal: Portal, agent: RunningAgent
):
    await agent.run(seconds=50)

    status = await agent.status()
    assert status.last_contact == portal.clock.now() - timedelta(seconds=10)
    assert status.wake_mode == "polling"
    assert status.poll_interval == 20


# --- Agent config -------------------------------------------------------------------


async def test_a_new_config_revision_reaches_the_agent_on_its_next_poll(
    portal: Portal, agent: RunningAgent, owner: Browser, operator: Browser
):
    before = (await agent.status()).config_revision
    await _config(owner, poll_interval="30", check_in_interval="600")

    await agent.run(seconds=20)

    status = await agent.status()
    assert status.config_revision == (before or 0) + 1
    assert status.poll_interval == 30
    await agent.run(seconds=29)
    assert _seen(await _card(operator, agent)) == portal.clock.now() - timedelta(
        seconds=29
    )
    await agent.run(seconds=1)
    assert _seen(await _card(operator, agent)) == portal.clock.now()


async def test_the_config_survives_a_restart_and_a_fresh_agent_uses_defaults(
    portal: Portal, agent: RunningAgent, owner: Browser
):
    await _config(owner, poll_interval="30")
    await agent.run(seconds=20)
    revision = (await agent.status()).config_revision

    agent.reachable = False
    await agent.restart()

    status = await agent.status()
    assert status.config_revision == revision
    assert status.poll_interval == 30

    (agent.state_dir / "agent_config.json").unlink()
    await agent.restart()
    status = await agent.status()
    assert status.config_revision is None
    assert status.poll_interval == 20
    assert status.tunnel_url == "wss://sp-rtk-base.big-spray.com/agent/tunnel"


async def test_the_owner_edits_the_config_on_the_portal(portal: Portal, owner: Browser):
    await _config(
        owner,
        poll_interval="25",
        metered_poll_interval="90",
        check_in_interval="600",
        doorbell_host="bell.example.net",
        doorbell_port="4500",
        tunnel_url="wss://sp-rtk-base.big-spray.com/agent/tunnel",
        tunnel_idle_timeout="300",
        tunnel_hard_cap="7200",
    )

    page = fields((await owner.get("/settings")).text)
    assert page["config-revision"] == ["2"]
    assert page["config-poll_interval"] == ["25"]
    assert page["config-doorbell_host"] == ["bell.example.net"]


@pytest.mark.parametrize(
    "values",
    [
        {"poll_interval": "1"},
        {"tunnel_url": "wss://elsewhere.example.com/agent/tunnel"},
        {"tunnel_url": "ws://sp-rtk-base.big-spray.com/agent/tunnel"},
        {"doorbell_host": "bell.example.net"},  # no port
        {"doorbell_port": "70000", "doorbell_host": "bell.example.net"},
    ],
)
async def test_the_portal_refuses_a_config_the_agent_would_ignore(
    portal: Portal, owner: Browser, values: dict[str, str]
):
    resp = await owner.action("/settings/agent-config", values)

    assert resp.status_code == 400
    assert resp.json()["error"]
    assert fields((await owner.get("/settings")).text)["config-revision"] == ["1"]


async def test_only_the_portal_owner_reaches_the_settings(
    portal: Portal, operator: Browser
):
    assert (await operator.get("/settings")).status_code == 403
    resp = await operator.action("/settings/agent-config", {"poll_interval": "30"})
    assert resp.status_code == 403
    resp = await operator.action("/settings/notices", {"text": "Hi"})
    assert resp.status_code == 403


async def test_a_tunnel_url_on_another_host_is_ignored_and_logged(
    portal: Portal, agent: RunningAgent, caplog
):
    # A compromised Portal: the bad value goes straight into its database
    # (no seam: /settings refuses a tunnel URL on another host).
    await portal.query(
        "INSERT INTO agent_config (revision, config, created_at) VALUES (7, %s, %s)",
        '{"revision": 7, "tunnel_url": "wss://evil.example.com/agent/tunnel"}',
        portal.clock.now(),
    )
    with caplog.at_level(logging.WARNING):
        await agent.run(seconds=20)

    status = await agent.status()
    assert status.config_revision == 7
    assert status.tunnel_url == "wss://sp-rtk-base.big-spray.com/agent/tunnel"
    assert "wss://evil.example.com/agent/tunnel" in caplog.text


async def test_a_doorbell_host_resolving_to_a_private_address_is_ignored(
    portal: Portal, agent: RunningAgent, owner: Browser, operator: Browser, caplog
):
    agent.dns.records["bell.example.net"] = ["93.184.215.14"]
    await _config(owner, doorbell_host="bell.example.net", doorbell_port="4500")
    await agent.run(minutes=5, seconds=20)
    card = await _card(operator, agent)
    assert card["doorbell"] == ["Doorbell: unavailable"]
    assert card["wake-mode"] == ["Polling every 20 s"]

    # Later the name is pointed into the base's LAN: caught at the next use.
    agent.dns.records["bell.example.net"] = ["192.168.1.1"]
    with caplog.at_level(logging.WARNING):
        await agent.run(minutes=5)

    card = await _card(operator, agent)
    assert card["doorbell"] == ["Doorbell: ignored"]
    assert card["wake-mode"] == ["Polling every 20 s"]
    assert (await agent.status()).doorbell == "ignored"
    assert "bell.example.net" in caplog.text and "192.168.1.1" in caplog.text


# --- Notices and versions ---------------------------------------------------------


async def test_a_notice_set_on_the_portal_shows_on_the_base_and_its_local_page(
    portal: Portal, agent: RunningAgent, owner: Browser, operator: Browser
):
    text = "Protocol 1 is supported until 2027-06-01."
    resp = await owner.action("/settings/notices", {"text": text})
    assert resp.status_code == 200, resp.text

    await agent.run(seconds=20)

    assert (await agent.status()).notices == [text]
    assert (await _card(operator, agent))["notice"] == [text]

    [notice_id] = re.findall(
        r'data-notice="(\d+)"', (await owner.get("/settings")).text
    )
    resp = await owner.action(f"/settings/notices/{notice_id}/delete")
    assert resp.status_code == 200
    await agent.run(seconds=20)
    assert (await agent.status()).notices == []
    assert "notice" not in await _card(operator, agent)


async def test_an_update_available_is_shown_as_information(
    portal: Portal, agent: RunningAgent, owner: Browser, operator: Browser
):
    assert "update" not in await _card(operator, agent)

    resp = await owner.action("/settings/latest-release", {"version": "99.0.0"})
    assert resp.status_code == 200, resp.text
    card = await _card(operator, agent)
    assert card["update"] == ["sp-rtk-base 99.0.0 available"]
    assert card["state"] == ["Online"]

    await owner.action("/settings/latest-release", {"version": base_version})
    assert "update" not in await _card(operator, agent)


async def test_an_unsupported_agent_gets_426_and_the_base_needs_upgrade(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    settings = portal.context.settings
    portal.context.settings = dataclasses.replace(
        settings, min_protocol_version=PROTOCOL_VERSION + 1
    )
    base_id = (await agent.status()).base_id

    await agent.run(seconds=20)

    status = await agent.status()
    assert status.needs_upgrade
    assert status.state == "connected" and status.base_id == base_id
    card = await _card(operator, agent)
    assert card["state"] == ["Needs upgrade"]
    refused_at = _seen(card)

    # Not offline, however long it stays quiet; it asks again once a day.
    await agent.run(hours=23, minutes=59)
    card = await _card(operator, agent)
    assert card["state"] == ["Needs upgrade"]
    assert _seen(card) == refused_at
    await agent.run(minutes=1)
    assert _seen(await _card(operator, agent)) == portal.clock.now()

    # sp-rtk-base is upgraded: same key, same Claim, polling again.
    agent.protocol_version = PROTOCOL_VERSION + 1
    await agent.restart()
    card = await _card(operator, agent)
    assert card["state"] == ["Online"]
    assert card["protocol"] == [f"Protocol {PROTOCOL_VERSION + 1}"]
    status = await agent.status()
    assert not status.needs_upgrade
    assert status.base_id == base_id
    assert len(await portal.query("SELECT id FROM base")) == 1


async def test_a_claim_from_an_unsupported_agent_gets_426(portal: Portal):
    portal.context.settings = dataclasses.replace(
        portal.context.settings, min_protocol_version=PROTOCOL_VERSION + 1
    )
    async with running_agent(portal) as a:
        with pytest.raises(Exception, match="Upgrade sp-rtk-base"):
            await a.connect()
    assert await portal.query("SELECT * FROM pairing") == []


# --- Request guard --------------------------------------------------------------------


@pytest.mark.parametrize(
    "path", ["/bases/{id}/metered", "/settings/agent-config", "/settings/notices"]
)
@pytest.mark.parametrize("missing", ["header", "origin", "json"])
async def test_state_changing_requests_are_under_the_request_guard(
    portal: Portal,
    agent: RunningAgent,
    owner: Browser,
    path: str,
    missing: str,
):
    url = path.format(id=(await agent.status()).base_id)
    headers = {"X-Portal-Action": "1", "Origin": portal.origin}
    if missing == "header":
        del headers["X-Portal-Action"]
    if missing == "origin":
        headers["Origin"] = "null"
    if missing == "json":
        resp = await owner.http.post(url, data={"metered": "true"}, headers=headers)
    else:
        resp = await owner.http.post(url, json={"metered": "true"}, headers=headers)

    assert resp.status_code == 403


async def test_only_the_operator_marks_their_base_metered(
    portal: Portal, agent: RunningAgent, owner: Browser
):
    base_id = (await agent.status()).base_id

    resp = await owner.action(f"/bases/{base_id}/metered", {"metered": "true"})

    assert resp.status_code == 404
    [base] = await portal.query("SELECT metered FROM base")
    assert base["metered"] is False


async def test_a_poll_from_an_unknown_key_is_unclaimed(portal: Portal):
    async with signing_agent(portal) as stranger:
        resp = await stranger.post("/agent/poll", {})
        check_in = await stranger.post("/agent/check-in", {})

    assert resp.status_code == 401
    assert resp.json()["error"] == "unclaimed"
    assert check_in.status_code == 401


# --- Cost ---------------------------------------------------------------------------

MONTH_S = 30 * 24 * 3600
TRANSPORT_OVERHEAD = 400
"""Bytes per request/response pair beyond HTTP: TLS 1.3 record framing
(2 x 22 B), TCP/IP headers for ~4 segments each way (8 x 52 B), on a
connection kept alive between polls. A new TLS session per poll would add
~5 kB (certificate chain), which keep-alive avoids at 20 s."""
CLOUDFLARE_HEADERS = 700
"""Response headers Cloudflare adds (date, server, cf-ray, alt-svc, nel,
report-to, ...), which the in-process app doesn't."""


async def test_polling_costs_at_most_half_a_gigabyte_a_month(
    portal: Portal, agent: RunningAgent
):
    agent.traffic.__init__()
    await agent.run(hours=1)

    t = agent.traffic
    per_hour = (
        t.sent + t.received + t.requests * (TRANSPORT_OVERHEAD + CLOUDFLARE_HEADERS)
    )
    per_month = per_hour * MONTH_S / 3600
    print(
        f"\n{t.requests} requests/h, {t.sent / t.requests:.0f} B up and "
        f"{t.received / t.requests:.0f} B down each (HTTP); "
        f"~{per_month / 1e6:.0f} MB/month with {TRANSPORT_OVERHEAD} B/request "
        f"transport overhead and {CLOUDFLARE_HEADERS} B of Cloudflare headers"
    )
    assert t.requests == 180 + 12  # polls every 20 s, Check-ins every 5 min
    assert per_month <= 0.5e9
