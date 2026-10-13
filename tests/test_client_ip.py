"""Seam 1: whose IP the Portal believes (ticket #98).

``CF-Connecting-IP`` is the client's IP only on the trusted path: a request
whose peer is in ``Settings.trusted_proxies`` (the pod network: ``cloudflared``
for the internet, Traefik for the LAN). Without a valid one, a trusted peer's
``X-Real-Ip`` is (Traefik's ``websecure`` entrypoint sets it to the LAN
client). Anything else, or a request with neither, has no client IP: rate limits key it
with every other untrusted request, possible-copy detection ignores it and
audit entries carry no IP. The pairing page, which shows where a Claim was
started from, makes that visible.
"""

from __future__ import annotations

import pytest

from .harness.fake_authentik import FakeAuthentik
from .harness.portal import CLOUDFLARED, Browser, Portal
from .harness.signer import SigningAgent, signing_agent

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"
SPOOFED = "192.0.2.99"
STRANGER = "198.18.0.5"
"""A peer that isn't ``cloudflared``: e.g. a client of a forgotten port
forward."""
TRAEFIK = "10.244.1.40"
"""A Traefik pod: the LAN route's peer, in the trusted pod network."""
LAN_CLIENT = "192.168.50.23"


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


async def _pairing_page(agent: SigningAgent, operator: Browser) -> str:
    resp = await agent.post("/agent/claims", {"name": "pi-north"})
    assert resp.status_code == 200, resp.text
    page = await operator.get(f"/claim?code={resp.json()['user_code']}")
    assert page.status_code == 200
    return page.text


async def test_cf_connecting_ip_through_cloudflared_is_the_client_ip(
    portal: Portal, operator: Browser
):
    async with signing_agent(portal, ip="198.51.100.20") as agent:
        page = await _pairing_page(agent, operator)

    assert "from 198.51.100.20" in page


async def test_cf_connecting_ip_from_any_other_peer_is_not_believed(
    portal: Portal, operator: Browser
):
    async with signing_agent(portal, ip=SPOOFED, peer=STRANGER) as agent:
        page = await _pairing_page(agent, operator)

    assert SPOOFED not in page
    assert STRANGER not in page


async def test_x_real_ip_through_traefik_on_the_lan_is_the_client_ip(
    portal: Portal, operator: Browser
):
    async with signing_agent(portal, ip=None, peer=TRAEFIK, real_ip=LAN_CLIENT) as a:
        page = await _pairing_page(a, operator)

    assert f"from {LAN_CLIENT}" in page


async def test_cf_connecting_ip_wins_over_x_real_ip(portal: Portal, operator: Browser):
    async with signing_agent(portal, ip="198.51.100.20", real_ip=LAN_CLIENT) as a:
        page = await _pairing_page(a, operator)

    assert "from 198.51.100.20" in page
    assert LAN_CLIENT not in page


async def test_x_real_ip_is_used_when_cf_connecting_ip_isnt_an_ip(
    portal: Portal, operator: Browser
):
    async with signing_agent(
        portal, ip="not-an-ip", peer=TRAEFIK, real_ip=LAN_CLIENT
    ) as a:
        page = await _pairing_page(a, operator)

    assert f"from {LAN_CLIENT}" in page


async def test_x_real_ip_from_any_other_peer_is_not_believed(
    portal: Portal, operator: Browser
):
    async with signing_agent(portal, ip=None, peer=STRANGER, real_ip=SPOOFED) as a:
        page = await _pairing_page(a, operator)

    assert SPOOFED not in page
    assert STRANGER not in page


async def test_an_x_real_ip_that_isnt_an_ip_is_ignored(
    portal: Portal, operator: Browser
):
    async with signing_agent(portal, ip=None, peer=TRAEFIK, real_ip="lan-box") as a:
        page = await _pairing_page(a, operator)

    assert "lan-box" not in page
    assert TRAEFIK not in page
    assert " from " not in page.split("Requested", 1)[1].split("</dd>", 1)[0]


async def test_a_request_without_cf_connecting_ip_has_no_client_ip(
    portal: Portal, operator: Browser
):
    async with signing_agent(portal, ip=None) as agent:
        page = await _pairing_page(agent, operator)

    assert CLOUDFLARED not in page
    assert " from " not in page.split("Requested", 1)[1].split("</dd>", 1)[0]


async def test_a_cf_connecting_ip_that_isnt_an_ip_is_ignored(
    portal: Portal, operator: Browser
):
    async with signing_agent(portal, ip="not-an-ip") as agent:
        page = await _pairing_page(agent, operator)

    assert "not-an-ip" not in page


async def test_audit_entries_carry_no_ip_for_an_untrusted_request(
    portal: Portal, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, PASSWORD)
    async with portal.browser(ip=SPOOFED, peer=STRANGER) as b:
        assert (await b.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}

    rows = await portal.query(
        "SELECT host(ip) AS ip FROM audit_entry WHERE kind = 'login'"
    )
    assert rows == [{"ip": None}]
