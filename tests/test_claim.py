"""Claim: pairing (RFC 8628) between a base's agent and a signed-in Operator.

The agent's side is driven here by ``SigningAgent`` (signed with the protocol
package), so misbehaviour can be scripted; ``test_claim_agent.py`` runs the
real Portal agent.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

import pytest

from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser, Portal
from .harness.signer import SigningAgent, signing_agent

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"
ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"


@pytest.fixture
async def agent(portal: Portal) -> AsyncIterator[SigningAgent]:
    async with signing_agent(portal) as a:
        yield a


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


async def start(agent: SigningAgent, name: str = "pi-north") -> dict:
    resp = await agent.post(
        "/agent/claims", {"name": name, "software_version": "0.11.0"}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def poll(agent: SigningAgent, device_code: str, **kwargs):
    return await agent.post(
        "/agent/claims/token", {"device_code": device_code}, **kwargs
    )


async def test_starting_a_claim_gives_a_code_and_where_to_approve_it(
    portal: Portal, agent: SigningAgent
):
    started = await start(agent, name="pi-north")

    assert re.fullmatch(f"[{ALPHABET}]{{8}}", started["user_code"])
    assert started["expires_in"] == 600
    assert started["interval"] == 5
    assert len(started["device_code"]) >= 32
    assert started["verification_uri"] == f"{portal.origin}/claim"
    assert (
        started["verification_uri_complete"]
        == f"{portal.origin}/claim?code={started['user_code']}"
    )
    assert "pi-north" not in started["verification_uri_complete"]


async def test_until_approved_the_agent_is_told_to_keep_waiting(
    portal: Portal, agent: SigningAgent
):
    started = await start(agent)

    resp = await poll(agent, started["device_code"])

    assert resp.status_code == 400
    assert resp.json()["error"] == "authorization_pending"


async def test_approving_claims_the_base_for_the_operator(
    portal: Portal, agent: SigningAgent, operator: Browser
):
    started = await start(agent, name="pi-north")

    page = await operator.get(f"/claim?code={started['user_code']}")
    assert page.status_code == 200
    assert "pi-north" in page.text and "0.11.0" in page.text
    approved = await operator.action(
        "/claim", {"code": started["user_code"], "name": "North field"}
    )
    assert approved.json() == {"next": "/"}

    listing = await operator.get("/")
    assert "North field" in listing.text
    assert "Never seen" in listing.text

    resp = await poll(agent, started["device_code"])
    assert resp.status_code == 200, resp.text
    claimed = resp.json()
    assert claimed["account"] == EMAIL
    assert re.fullmatch("[a-z2-7]{10}", claimed["base_id"])

    [base] = await portal.query("SELECT * FROM base")
    assert base["id"] == claimed["base_id"]
    assert base["name"] == "North field"
    [account] = await portal.query("SELECT id FROM account WHERE email = %s", EMAIL)
    assert base["owner_account_id"] == account["id"]
    # Only the public key: exactly the agent's public JWK, nothing else.
    assert base["public_key"] == agent.key.public_jwk
    assert base["key_thumbprint"] == agent.key.thumbprint


async def test_the_claim_is_audited(
    portal: Portal, agent: SigningAgent, operator: Browser
):
    started = await start(agent)
    await operator.action("/claim", {"code": started["user_code"], "name": "North"})
    claimed = (await poll(agent, started["device_code"])).json()

    [entry] = await portal.query("SELECT * FROM audit_entry WHERE kind = 'claim'")
    assert entry["base_id"] == claimed["base_id"]
    assert entry["detail"]["name"] == "North"
    assert str(entry["ip"]) == "203.0.113.7"


async def test_the_code_can_be_typed_in_lower_case_with_a_dash(
    agent: SigningAgent, operator: Browser
):
    code = (await start(agent))["user_code"]
    typed = f"{code[:4]}-{code[4:]}".lower()

    resp = await operator.action("/claim", {"code": typed, "name": "North"})

    assert resp.json() == {"next": "/"}


async def test_the_display_name_is_required(agent: SigningAgent, operator: Browser):
    code = (await start(agent))["user_code"]

    resp = await operator.action("/claim", {"code": code, "name": "   "})

    assert resp.status_code == 400
    assert "name" in resp.json()["error"].lower()


async def test_a_wrong_code_fails_clearly_and_claims_nothing(
    portal: Portal, agent: SigningAgent, operator: Browser
):
    await start(agent)

    resp = await operator.action("/claim", {"code": "BBBBBBBB", "name": "North"})

    assert resp.status_code == 400
    assert resp.json()["error"] == (
        "No base is waiting for code BBBB-BBBB. Check the code on the base's "
        "Portal page."
    )
    assert await portal.query("SELECT * FROM base") == []


async def test_an_expired_code_fails_clearly_and_claims_nothing(
    portal: Portal, agent: SigningAgent, operator: Browser
):
    started = await start(agent)
    portal.clock.advance(minutes=10, seconds=1)

    resp = await operator.action(
        "/claim", {"code": started["user_code"], "name": "North"}
    )

    assert resp.status_code == 400
    assert resp.json()["error"] == (
        "That code has expired. Press Connect to Portal on the base again "
        "for a new one."
    )
    assert await portal.query("SELECT * FROM base") == []
    expired = await poll(agent, started["device_code"])
    assert expired.json()["error"] == "expired_token"


async def test_a_code_is_good_for_one_claim(agent: SigningAgent, operator: Browser):
    code = (await start(agent))["user_code"]
    await operator.action("/claim", {"code": code, "name": "North"})

    again = await operator.action("/claim", {"code": code, "name": "South"})

    assert again.status_code == 400
    assert again.json()["error"] == "That code has already been used."


async def test_the_claim_page_says_when_a_code_is_unknown(operator: Browser):
    page = await operator.get("/claim?code=BBBBBBBB")

    assert page.status_code == 200
    assert "No base is waiting for code BBBB-BBBB" in page.text


async def test_approving_needs_a_session_and_comes_back_after_sign_in(
    portal: Portal, agent: SigningAgent, authentik: FakeAuthentik
):
    code = (await start(agent))["user_code"]
    authentik.add_user(EMAIL, PASSWORD)
    async with portal.browser() as browser:
        page = await browser.get(f"/claim?code={code}")
        assert page.status_code == 303
        assert page.headers["location"] == f"/login?next=/claim?code={code}"

        login = await browser.get(page.headers["location"])
        assert 'name="next"' in login.text
        resp = await browser.action(
            "/login",
            {"email": EMAIL, "password": PASSWORD, "next": f"/claim?code={code}"},
        )
        assert resp.json() == {"next": f"/claim?code={code}"}


@pytest.mark.parametrize("bad", ["https://evil.example/", "//evil.example/", "/\\x"])
async def test_sign_in_never_returns_to_another_site(
    browser: Browser, authentik: FakeAuthentik, bad: str
):
    authentik.add_user(EMAIL, PASSWORD)

    resp = await browser.action(
        "/login", {"email": EMAIL, "password": PASSWORD, "next": bad}
    )

    assert resp.json() == {"next": "/"}


async def test_another_key_cannot_collect_the_claim(
    agent: SigningAgent, operator: Browser
):
    started = await start(agent)
    await operator.action("/claim", {"code": started["user_code"], "name": "North"})

    from sp_rtk_portal_protocol import BaseKey

    resp = await poll(agent, started["device_code"], key=BaseKey.generate())

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


async def test_an_unknown_device_code_is_refused(agent: SigningAgent):
    resp = await poll(agent, "no-such-code")

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


async def test_polling_faster_than_the_interval_is_told_to_slow_down(
    portal: Portal, agent: SigningAgent
):
    started = await start(agent)
    await poll(agent, started["device_code"])

    portal.clock.advance(seconds=2)
    fast = await poll(agent, started["device_code"])
    portal.clock.advance(seconds=5)
    ok = await poll(agent, started["device_code"])

    assert fast.json()["error"] == "slow_down"
    assert ok.json()["error"] == "authorization_pending"


async def test_the_26th_claim_on_an_account_is_refused_naming_the_limit(
    portal: Portal, operator: Browser
):
    for n in range(25):
        async with signing_agent(portal) as a:
            code = (await start(a))["user_code"]
            assert (
                await operator.action("/claim", {"code": code, "name": f"b{n}"})
            ).json() == {"next": "/"}

    async with signing_agent(portal) as a:
        code = (await start(a))["user_code"]
        resp = await operator.action("/claim", {"code": code, "name": "one more"})

    assert resp.status_code == 400
    assert resp.json()["error"] == (
        "You already have 25 bases, the most one account can Claim."
    )
    assert len(await portal.query("SELECT * FROM base")) == 25
