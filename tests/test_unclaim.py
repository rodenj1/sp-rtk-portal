"""Seam 1: Un-claim from the base and from the Portal (ticket #93).

Either way the Portal forgets the base (its record, key, Remote sessions and,
once #94 lands, its Shares) and the agent wipes its key and goes idle, so the
next Claim makes a new base with a new key and ``<id>``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
from sp_rtk_portal_protocol import RELEASE_PATH, BaseKey, ErrorReply

from sp_rtk_portal.bases.events import Unclaimed

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import base_ui
from .harness.fake_authentik import FakeAuthentik
from .harness.pages import base_card
from .harness.portal import Browser, Portal
from .harness.server import serving
from .harness.signer import signing_agent

EMAIL = "operator@example.com"
OTHER = "colleague@example.com"
PASSWORD = "correct horse battery staple"


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
async def colleague(portal: Portal, authentik: FakeAuthentik) -> AsyncIterator[Browser]:
    """Another signed-in user, who doesn't own the base."""
    authentik.add_user(OTHER, PASSWORD)
    async with portal.browser(ip="203.0.113.99") as b:
        assert (await b.sign_in(OTHER, PASSWORD)).json() == {"next": "/"}
        yield b


@pytest.fixture
async def agent(portal: Portal, operator: Browser) -> AsyncIterator[RunningAgent]:
    async with running_agent(portal) as a:
        await a.claim(operator)
        yield a


async def base_of(agent: RunningAgent) -> str:
    base_id = (await agent.status()).base_id
    assert base_id
    return base_id


async def account_id(portal: Portal, email: str) -> int:
    [row] = await portal.query("SELECT id FROM account WHERE email = %s", email)
    return int(row["id"])


async def eventually(check: Callable[[], Awaitable[bool] | bool], what: str) -> None:
    for _ in range(500):
        result = check()
        if isinstance(result, Awaitable):
            result = await result
        if result:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"never: {what}")


def holds_no_key(agent: RunningAgent) -> bool:
    """Nothing of the Claim is left in the agent's state directory."""
    left = (
        sorted(p.name for p in agent.state_dir.glob("*"))
        if agent.state_dir.exists()
        else []
    )
    return left == []


async def assert_refused_by_the_proxy(
    browser: Browser, base_id: str, token: str
) -> None:
    """The ``/b/`` proxy refuses the path as a revoked token (as a frame load
    from the Session bar, so it isn't refused for being outside a frame)."""
    resp = await browser.http.get(
        f"/b/{base_id}/s/{token}/", headers={"Sec-Fetch-Dest": "iframe"}
    )
    assert resp.status_code == 403
    assert "has ended, or this link is not valid" in resp.text


# --- Local Un-claim ------------------------------------------------------------------


async def test_a_local_un_claim_releases_the_base_on_the_portal_and_wipes_its_key(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    assert base_card((await operator.get("/")).text, base_id)

    status = await agent.unclaim()

    assert status.state == "not_connected"
    assert status.base_id is None
    assert holds_no_key(agent)
    assert await portal.query("SELECT id FROM base") == []
    assert not base_card((await operator.get("/")).text, base_id)
    # Idle: the agent contacts the Portal no more.
    before = agent.traffic.requests
    await agent.run(minutes=10)
    assert agent.traffic.requests == before
    assert (await agent.status()).state == "not_connected"


async def test_a_local_un_claim_while_the_portal_is_unreachable_still_wipes_the_key(
    portal: Portal, agent: RunningAgent
):
    agent.reachable = False

    status = await agent.unclaim()

    assert status.state == "not_connected"
    assert holds_no_key(agent)
    # The Portal still lists it until the Operator Un-claims it there too.
    assert len(await portal.query("SELECT id FROM base")) == 1


async def test_a_release_from_an_unknown_key_is_refused_as_unclaimed(portal: Portal):
    async with signing_agent(portal) as signer:
        resp = await signer.post(RELEASE_PATH, {}, key=BaseKey.generate())

    assert resp.status_code == 401
    assert resp.json()["error"] == ErrorReply.UNCLAIMED


async def test_a_local_un_claim_is_audited(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    owner = await account_id(portal, EMAIL)
    thumbprint = agent.key.thumbprint

    await agent.unclaim()

    [entry] = await portal.query(
        "SELECT kind, account_id, base_id, host(ip) AS ip, at, detail"
        " FROM audit_entry WHERE kind = 'unclaim'"
    )
    assert entry["account_id"] == owner
    assert entry["base_id"] == base_id
    assert entry["ip"] == agent.ip
    assert entry["at"] == portal.clock.now()
    assert entry["detail"] == {
        "by": "base",
        "name": "North field",
        "key_thumbprint": thumbprint,
    }


# --- Un-claim on the Portal ----------------------------------------------------------


async def test_a_portal_un_claim_with_the_agent_offline_wipes_its_key_on_its_next_poll(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    agent.reachable = False

    resp = await operator.action(f"/bases/{base_id}/unclaim")

    assert resp.json() == {"next": "/"}, resp.text
    assert await portal.query("SELECT id FROM base") == []
    assert not base_card((await operator.get("/")).text, base_id)
    # Offline, the agent doesn't know yet.
    await agent.run(minutes=5)
    assert (await agent.status()).state == "connected"
    assert not holds_no_key(agent)

    agent.reachable = True
    status = await agent.until("not_connected")

    assert holds_no_key(agent)
    assert status.message and "Un-claimed on the Portal" in status.message
    before = agent.traffic.requests
    await agent.run(minutes=10)
    assert agent.traffic.requests == before


async def test_a_portal_un_claim_cuts_live_remote_sessions_and_refuses_their_tokens(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    owner = await account_id(portal, EMAIL)
    tunnels = portal.context.tunnels
    resp = await operator.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}
    session = tunnels.session_for(owner, base_id)
    assert session is not None
    token = session.token

    resp = await operator.action(f"/bases/{base_id}/unclaim")

    assert resp.json() == {"next": "/"}
    assert tunnels.lookup(base_id, token) is None
    assert tunnels.session_for(owner, base_id) is None
    assert tunnels.state(session) == "ended"
    assert session.end_reason == "un_claim"
    await assert_refused_by_the_proxy(operator, base_id, token)
    # Nor can anyone start a new one, or see its Session bar.
    assert (await operator.action(f"/bases/{base_id}/remote")).status_code == 404
    assert (await operator.get(f"/bases/{base_id}")).status_code == 404
    ends = await portal.query(
        "SELECT detail FROM audit_entry WHERE kind = 'remote_session_end'"
    )
    assert [e["detail"]["reason"] for e in ends] == ["un_claim"]


async def test_a_portal_un_claim_closes_an_open_tunnel(
    portal: Portal, operator: Browser
):
    async with (
        base_ui() as ui,
        serving(portal.app) as port,
        running_agent(portal, server_port=port, app_port=ui.port) as agent,
    ):
        await agent.claim(operator)
        base_id = await base_of(agent)
        await operator.action(f"/bases/{base_id}/remote")
        await agent.run(seconds=20)

        async def tunnel_open() -> bool:
            return (await agent.status()).tunnel == "open"

        await eventually(tunnel_open, "the tunnel opened")

        await operator.action(f"/bases/{base_id}/unclaim")

        assert not portal.context.tunnels.tunnel_up(base_id)
        status = await agent.until("not_connected")
        assert status.tunnel is None
        assert holds_no_key(agent)


async def test_a_portal_un_claim_is_audited_with_who_when_and_where(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    owner = await account_id(portal, EMAIL)
    thumbprint = agent.key.thumbprint

    await operator.action(f"/bases/{base_id}/unclaim")

    [entry] = await portal.query(
        "SELECT kind, account_id, base_id, host(ip) AS ip, at, detail"
        " FROM audit_entry WHERE kind = 'unclaim'"
    )
    assert entry["account_id"] == owner
    assert entry["base_id"] == base_id
    assert entry["ip"] == "203.0.113.7"
    assert entry["at"] == portal.clock.now()
    assert entry["detail"] == {
        "by": "portal",
        "name": "North field",
        "key_thumbprint": thumbprint,
    }


async def test_un_claim_is_a_state_changing_request_under_the_request_guard(
    portal: Portal, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)

    # A cross-site form post: no custom header, no JSON, another Origin.
    resp = await operator.http.post(
        f"/bases/{base_id}/unclaim",
        data={"x": "1"},
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403
    resp = await operator.http.post(f"/bases/{base_id}/unclaim", json={})
    assert resp.status_code == 403

    assert len(await portal.query("SELECT id FROM base")) == 1
    assert await portal.query("SELECT id FROM audit_entry WHERE kind = 'unclaim'") == []


async def test_only_the_operator_can_un_claim_a_base(
    portal: Portal, colleague: Browser, agent: RunningAgent
):
    # Shares are #94: until then a Shared user is just another account, and
    # #94 adds a real Share to this test.
    base_id = await base_of(agent)

    resp = await colleague.action(f"/bases/{base_id}/unclaim")

    assert resp.status_code == 404
    assert len(await portal.query("SELECT id FROM base")) == 1
    assert (await agent.status()).state == "connected"


async def test_signed_out_un_claim_is_refused(portal: Portal, agent: RunningAgent):
    base_id = await base_of(agent)
    async with portal.browser() as stranger:
        resp = await stranger.action(f"/bases/{base_id}/unclaim")
    assert resp.status_code == 401
    assert len(await portal.query("SELECT id FROM base")) == 1


async def test_the_base_list_offers_un_claim(operator: Browser, agent: RunningAgent):
    base_id = await base_of(agent)
    page = (await operator.get("/")).text
    assert base_card(page, base_id)["unclaim"] == ["Un-claim"]
    assert f'data-action="/bases/{base_id}/unclaim"' in page


@pytest.mark.parametrize("where", ["base", "portal"])
async def test_un_claim_runs_the_unclaimed_hooks_in_its_transaction(
    portal: Portal, operator: Browser, agent: RunningAgent, where: str
):
    # Shares (#94) hook in here to remove the base's Shares and Pending shares.
    base_id = await base_of(agent)
    owner = await account_id(portal, EMAIL)
    seen: list[tuple[Unclaimed, int]] = []

    async def record(conn, event: Unclaimed) -> None:
        cur = await conn.execute(
            "SELECT count(*) AS n FROM base WHERE id = %s", (base_id,)
        )
        row = await cur.fetchone()
        seen.append((event, row["n"]))

    portal.context.base_events.on_unclaimed(record)
    if where == "base":
        await agent.unclaim()
    else:
        await operator.action(f"/bases/{base_id}/unclaim")

    [(event, still_there)] = seen
    assert (event.base_id, event.owner_account_id, event.by) == (base_id, owner, where)
    assert event.at == portal.clock.now()
    assert still_there == 0  # it runs after the delete, before the commit


# --- Claiming again ------------------------------------------------------------------


@pytest.mark.parametrize("where", ["base", "portal"])
async def test_claiming_again_makes_a_new_base_and_the_old_id_is_gone(
    portal: Portal, operator: Browser, agent: RunningAgent, where: str
):
    old_id = await base_of(agent)
    old_key = agent.key.public_jwk
    owner = await account_id(portal, EMAIL)
    await operator.action(f"/bases/{old_id}/remote")
    old_token = portal.context.tunnels.session_for(owner, old_id).token  # type: ignore[union-attr]
    if where == "base":
        await agent.unclaim()
    else:
        await operator.action(f"/bases/{old_id}/unclaim")
        await agent.until("not_connected")

    reclaimed = await agent.claim(operator, name="North field")

    assert reclaimed.base_id and reclaimed.base_id != old_id
    assert agent.key.public_jwk != old_key
    [base] = await portal.query("SELECT id, public_key FROM base")
    assert base["id"] == reclaimed.base_id
    assert base["public_key"] == agent.key.public_jwk
    # The old id is gone everywhere: list, Session bar, Open remotely, /b/.
    page = (await operator.get("/")).text
    assert not base_card(page, old_id)
    assert base_card(page, reclaimed.base_id)
    assert (await operator.get(f"/bases/{old_id}")).status_code == 404
    assert (await operator.action(f"/bases/{old_id}/remote")).status_code == 404
    assert portal.context.tunnels.lookup(old_id, old_token) is None
    await assert_refused_by_the_proxy(operator, old_id, old_token)
