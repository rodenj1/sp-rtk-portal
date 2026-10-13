"""Seam 1: the real Portal agent pairs with the real Portal (ticket #86)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import pytest
from sp_rtk_base import __version__ as base_version
from sp_rtk_portal_protocol import BaseKey

from .harness.agent import RunningAgent, running_agent
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser, Portal

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"


@pytest.fixture
async def agent(portal: Portal) -> AsyncIterator[RunningAgent]:
    async with running_agent(portal) as a:
        yield a


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


async def _approve(operator: Browser, approve_url: str, name: str) -> None:
    """What the Operator does after pressing "Approve on Portal"."""
    url = urlsplit(approve_url)
    page = await operator.get(f"{url.path}?{url.query}")
    assert page.status_code == 200
    assert "pi-north" in page.text and base_version in page.text
    code = url.query.removeprefix("code=")
    resp = await operator.action("/claim", {"code": code, "name": name})
    assert resp.json() == {"next": "/"}, resp.text


async def test_the_agent_pairs_and_the_portal_holds_only_its_public_key(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    pairing = await agent.connect()
    assert pairing.state == "pairing"
    assert pairing.user_code and pairing.approve_url
    assert pairing.approve_url.startswith(f"{portal.origin}/claim?code=")

    await _approve(operator, pairing.approve_url, "North field")
    connected = await agent.until("connected")

    [base] = await portal.query("SELECT * FROM base")
    assert connected.base_id == base["id"]
    assert connected.account == EMAIL
    assert connected.portal == "sp-rtk-base.big-spray.com"
    assert connected.last_contact == portal.clock.now()
    assert base["name"] == "North field"
    [account] = await portal.query("SELECT id FROM account WHERE email = %s", EMAIL)
    assert base["owner_account_id"] == account["id"]
    assert base["software_version"] == base_version
    assert base["protocol_version"] == 1
    # The Portal holds the agent's public key, and only that.
    key = BaseKey.from_pem((agent.state_dir / "base_key.pem").read_bytes())
    assert base["public_key"] == key.public_jwk
    assert set(base["public_key"]) == {"kty", "crv", "x"}
    assert base["key_thumbprint"] == key.thumbprint
    # The id where the base's identity endpoint reads it.
    assert (agent.state_dir / "base_id").read_text().strip() == base["id"]
    # The base is in the Operator's list at once.
    assert "North field" in (await operator.get("/")).text


async def test_the_agent_starts_no_claim_until_asked(
    portal: Portal, agent: RunningAgent
):
    assert (await agent.status()).state == "not_connected"

    assert await portal.query("SELECT * FROM pairing") == []
    assert not agent.state_dir.exists()


async def test_a_restarted_or_reinstalled_agent_keeps_its_key_and_id(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    pairing = await agent.connect()
    assert pairing.approve_url
    await _approve(operator, pairing.approve_url, "North field")
    before = await agent.until("connected")
    key = (agent.state_dir / "base_key.pem").read_bytes()

    await agent.restart()  # a fresh agent over the same state directory
    after = await agent.status()

    assert after.state == "connected"
    assert after.base_id == before.base_id
    assert after.account == EMAIL
    assert (agent.state_dir / "base_key.pem").read_bytes() == key
    assert len(await portal.query("SELECT * FROM base")) == 1


async def test_an_unapproved_code_expires_and_nothing_is_claimed(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    pairing = await agent.connect()
    assert pairing.user_code

    status = await agent.until("not_connected")  # its polls move the clock on

    assert status.message and "expired" in status.message
    resp = await operator.action("/claim", {"code": pairing.user_code, "name": "Late"})
    assert resp.status_code == 400
    assert "expired" in resp.json()["error"]
    assert await portal.query("SELECT * FROM base") == []
    assert not agent.state_dir.exists()


async def test_the_pairing_request_comes_from_the_bases_public_ip(
    portal: Portal, agent: RunningAgent, operator: Browser
):
    pairing = await agent.connect()

    page = await operator.get(f"/claim?code={pairing.user_code}")

    assert agent.ip in page.text
