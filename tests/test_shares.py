"""Seam 1: Shares and Pending shares (ticket #94).

The Operator Claims a base through the real agent, then Shares it by email
on the base's Shares page. Email goes through a real SMTP conversation with
the fake server (``smtp``); what users see comes from the Portal's pages.
"""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack

import pytest
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.fake_authentik import FakeAuthentik
from .harness.fake_smtp import FakeSmtp
from .harness.pages import base_card, fields
from .harness.portal import Browser, Portal
from .harness.server import serving
from .harness.session_bar import status_channel

OPERATOR = "operator@example.com"
COLLEAGUE = "sam@example.com"
PASSWORD = "correct horse battery staple"
BASE_NAME = "North field"


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(OPERATOR, PASSWORD)
    assert (await browser.sign_in(OPERATOR, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
async def server(portal: Portal) -> AsyncIterator[int]:
    async with serving(portal.app) as port:
        yield port


@pytest.fixture
async def ui() -> AsyncIterator[BaseUi]:
    async with base_ui() as stub:
        yield stub


@pytest.fixture
async def agent(
    portal: Portal, operator: Browser, server: int, ui: BaseUi
) -> AsyncIterator[RunningAgent]:
    async with running_agent(portal, server_port=server, app_port=ui.port) as a:
        await a.claim(operator, BASE_NAME)
        yield a


@pytest.fixture
async def base_id(agent: RunningAgent) -> str:
    base_id = (await agent.status()).base_id
    assert base_id
    return base_id


class Users:
    """Other people's browsers, each signed in as one email."""

    def __init__(self, portal: Portal, stack: AsyncExitStack) -> None:
        self.portal = portal
        self.stack = stack

    async def sign_in(self, email: str, *, verified: bool = True) -> Browser:
        """A new browser signed in as ``email`` (Authentik user made if new)."""
        if email.lower() not in self.portal.authentik.users:
            self.portal.authentik.add_user(email, PASSWORD, email_verified=verified)
        b = await self.stack.enter_async_context(self.portal.browser(ip="198.51.100.9"))
        assert (await b.sign_in(email, PASSWORD)).json() == {"next": "/"}
        return b


@pytest.fixture
async def users(portal: Portal) -> AsyncIterator[Users]:
    async with AsyncExitStack() as stack:
        yield Users(portal, stack)


async def share(operator: Browser, base_id: str, email: str) -> dict:
    resp = await operator.action(f"/bases/{base_id}/shares", {"email": email})
    return resp.json() | {"status": resp.status_code}


# --- Sharing --------------------------------------------------------------------


async def test_sharing_with_an_existing_verified_account_grants_it_at_once(
    portal: Portal, operator: Browser, base_id: str, users: Users, smtp: FakeSmtp
):
    colleague = await users.sign_in(COLLEAGUE)

    reply = await share(operator, base_id, COLLEAGUE)

    assert reply == {"next": f"/bases/{base_id}/shares", "status": 200}
    card = base_card((await colleague.get("/")).text, base_id)
    assert card["shared"] == ["Shared"]
    [invite] = smtp.to(COLLEAGUE)
    assert BASE_NAME in invite.subject
    assert OPERATOR in invite.body
    assert f"{portal.origin}/" in invite.body
    [notice] = smtp.to(OPERATOR)
    assert BASE_NAME in notice.body and COLLEAGUE in notice.body


async def test_sharing_with_an_unknown_email_creates_a_pending_share(
    portal: Portal, operator: Browser, base_id: str, smtp: FakeSmtp
):
    reply = await share(operator, base_id, "New.Person@Example.com")

    assert reply == {"next": f"/bases/{base_id}/shares", "status": 200}
    page = fields((await operator.get(f"/bases/{base_id}/shares")).text)
    assert page["pending-share"] == ["new.person@example.com"]
    assert "shared-user" not in page
    [invite] = smtp.to("new.person@example.com")
    assert BASE_NAME in invite.subject
    assert f"{portal.origin}/signup" in invite.body
    assert "2026-01-15" in invite.body  # expires in 14 days
    [notice] = smtp.to(OPERATOR)
    assert BASE_NAME in notice.body and "new.person@example.com" in notice.body


async def test_an_unverified_account_only_gets_a_pending_share(
    portal: Portal, operator: Browser, base_id: str, users: Users
):
    unverified = await users.sign_in(COLLEAGUE, verified=False)

    await share(operator, base_id, COLLEAGUE)

    assert base_id not in (await unverified.get("/")).text
    page = fields((await operator.get(f"/bases/{base_id}/shares")).text)
    assert page["pending-share"] == [COLLEAGUE]


async def test_a_pending_share_converts_on_the_first_login_with_that_verified_email(
    portal: Portal, operator: Browser, base_id: str, users: Users, clock
):
    await share(operator, base_id, COLLEAGUE)
    clock.advance(days=13, hours=23)

    colleague = await users.sign_in(COLLEAGUE)

    card = base_card((await colleague.get("/")).text, base_id)
    assert card["shared"] == ["Shared"]
    page = fields((await operator.get(f"/bases/{base_id}/shares")).text)
    assert page["shared-user"] == [COLLEAGUE]
    assert "pending-share" not in page


async def test_a_pending_share_expires_after_14_days(
    portal: Portal, operator: Browser, base_id: str, users: Users, clock
):
    await share(operator, base_id, COLLEAGUE)
    clock.advance(days=14)

    colleague = await users.sign_in(COLLEAGUE)

    assert base_id not in (await colleague.get("/")).text
    page = fields((await operator.get(f"/bases/{base_id}/shares")).text)
    assert "pending-share" not in page and "shared-user" not in page


# --- What a Shared user can do --------------------------------------------------------

FRAMED = {"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Mode": "navigate"}


@pytest.fixture
async def colleague(
    operator: Browser, base_id: str, users: Users, smtp: FakeSmtp
) -> Browser:
    """Sam, signed in, with a Share of the Operator's base."""
    b = await users.sign_in(COLLEAGUE)
    assert (await share(operator, base_id, COLLEAGUE))["status"] == 200
    return b


async def open_remotely(
    who: Browser, agent: RunningAgent, server: int, base_id: str
) -> str:
    """Open remotely until Connected; the frame's path (``/b/…/``)."""
    resp = await who.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}, resp.text
    async with status_channel(server, who, base_id) as bar:
        await agent.run(seconds=20)  # the poll that carries the Wake
        connected = await bar.until("connected")
    return str(connected["frame"])


async def frame_ws(server: int, frame: str) -> ClientConnection:
    ws = await connect(f"ws://127.0.0.1:{server}{frame}ws")
    await ws.send("hello")
    assert await asyncio.wait_for(ws.recv(), 5) == "echo hello"
    return ws


async def assert_cut(ws: ClientConnection, who: Browser, server: int, frame: str):
    with pytest.raises(ConnectionClosed):
        await asyncio.wait_for(ws.recv(), 5)
    assert (await who.get(frame, headers=FRAMED)).status_code == 403
    with pytest.raises(InvalidStatus) as refused:
        await connect(f"ws://127.0.0.1:{server}{frame}ws")
    assert refused.value.response.status_code == 403


async def test_a_shared_user_opens_the_base_like_its_operator(
    colleague: Browser, agent: RunningAgent, server: int, base_id: str, ui: BaseUi
):
    session_bar = await colleague.get(f"/bases/{base_id}")
    assert session_bar.status_code == 200

    frame = await open_remotely(colleague, agent, server, base_id)

    resp = await colleague.get(frame + "survey", headers=FRAMED)
    assert (resp.status_code, resp.text) == (200, "base page /survey")
    assert ui.seen[-1].path == "/survey"


async def test_a_shared_user_cannot_share_the_base(
    colleague: Browser, base_id: str, smtp: FakeSmtp
):
    sent = len(smtp.outbox)

    reply = await share(colleague, base_id, "third@example.com")

    assert reply == {"error": "Only the base's Operator can Share it.", "status": 403}
    assert (await colleague.get(f"/bases/{base_id}/shares")).status_code == 404
    assert len(smtp.outbox) == sent


async def test_a_stranger_cannot_share_or_open_the_base(base_id: str, users: Users):
    stranger = await users.sign_in("eve@example.com")

    assert (await share(stranger, base_id, "eve2@example.com"))["status"] == 404
    resp = await stranger.action(f"/bases/{base_id}/remote")
    assert resp.status_code == 404


# --- Taking a Share away ----------------------------------------------------------------


async def test_removing_a_share_cuts_the_shared_users_live_session_at_once(
    portal: Portal,
    operator: Browser,
    colleague: Browser,
    agent: RunningAgent,
    server: int,
    base_id: str,
):
    frame = await open_remotely(colleague, agent, server, base_id)
    ws = await frame_ws(server, frame)
    [shared] = await portal.query("SELECT id FROM account WHERE email = %s", COLLEAGUE)

    resp = await operator.action(f"/bases/{base_id}/shares/{shared['id']}/remove")

    assert resp.json() == {"next": f"/bases/{base_id}/shares"}
    await assert_cut(ws, colleague, server, frame)
    assert base_id not in (await colleague.get("/")).text
    assert (await colleague.action(f"/bases/{base_id}/remote")).status_code == 404


async def test_leaving_a_share_cuts_the_live_session_and_drops_the_base(
    operator: Browser,
    colleague: Browser,
    agent: RunningAgent,
    server: int,
    base_id: str,
):
    frame = await open_remotely(colleague, agent, server, base_id)
    ws = await frame_ws(server, frame)
    operator_frame = await open_remotely(operator, agent, server, base_id)

    resp = await colleague.action(f"/bases/{base_id}/leave")

    assert resp.json() == {"next": "/"}
    await assert_cut(ws, colleague, server, frame)
    assert base_id not in (await colleague.get("/")).text
    # The Operator's own Remote session carries on.
    still = await operator.get(operator_frame + "survey", headers=FRAMED)
    assert still.status_code == 200


# --- Limits ---------------------------------------------------------------------------------


async def test_the_21st_shared_user_is_refused(
    operator: Browser, base_id: str, users: Users
):
    for n in range(21):
        await users.sign_in(f"user{n}@example.com")
    for n in range(20):
        assert (await share(operator, base_id, f"user{n}@example.com"))["status"] == 200

    reply = await share(operator, base_id, "user20@example.com")

    assert reply["status"] == 400
    assert "20 Shared users" in reply["error"]
    page = fields((await operator.get(f"/bases/{base_id}/shares")).text)
    assert len(page["shared-user"]) == 20


async def test_the_11th_pending_share_is_refused(operator: Browser, base_id: str):
    for n in range(10):
        assert (await share(operator, base_id, f"new{n}@example.com"))["status"] == 200

    reply = await share(operator, base_id, "new10@example.com")

    assert reply["status"] == 400
    assert "10 Pending shares" in reply["error"]


async def test_expired_pending_shares_no_longer_count(
    operator: Browser, base_id: str, clock
):
    for n in range(10):
        await share(operator, base_id, f"new{n}@example.com")
    clock.advance(days=14)

    assert (await share(operator, base_id, "new10@example.com"))["status"] == 200


async def test_the_limits_are_configurable(
    portal: Portal, operator: Browser, base_id: str, users: Users
):
    portal.context.settings = dataclasses.replace(
        portal.context.settings,
        max_shared_users_per_base=1,
        max_pending_shares_per_base=1,
    )
    await users.sign_in("a@example.com")
    await users.sign_in("b@example.com")
    await share(operator, base_id, "a@example.com")
    await share(operator, base_id, "new@example.com")

    shared = await share(operator, base_id, "b@example.com")
    pending = await share(operator, base_id, "new2@example.com")

    assert "1 Shared users" in shared["error"]
    assert "1 Pending shares" in pending["error"]


async def test_sharing_twice_or_with_yourself_is_refused(
    operator: Browser, base_id: str, users: Users
):
    await users.sign_in(COLLEAGUE)
    await share(operator, base_id, COLLEAGUE)
    await share(operator, base_id, "new@example.com")

    for email in (COLLEAGUE, "NEW@example.com", OPERATOR, "not an email"):
        assert (await share(operator, base_id, email))["status"] == 400, email


# --- Audit ------------------------------------------------------------------------------------


async def share_audit(portal: Portal) -> list[dict]:
    """The Share entries (the audit page comes later: read the database)."""
    return await portal.query(
        "SELECT e.kind, a.email AS actor, e.base_id, host(e.ip) AS ip,"
        " e.detail->>'email' AS email"
        " FROM audit_entry e LEFT JOIN account a ON a.id = e.account_id"
        " WHERE e.kind LIKE '%%share%%' ORDER BY e.id"
    )


async def test_every_share_action_is_audited(
    portal: Portal, operator: Browser, base_id: str, users: Users
):
    colleague = await users.sign_in(COLLEAGUE)
    await share(operator, base_id, COLLEAGUE)
    await share(operator, base_id, "new@example.com")
    newcomer = await users.sign_in("new@example.com")  # converts
    [new] = await portal.query(
        "SELECT id FROM account WHERE email = %s", "new@example.com"
    )
    await operator.action(f"/bases/{base_id}/shares/{new['id']}/remove")
    await colleague.action(f"/bases/{base_id}/leave")
    await share(operator, base_id, "later@example.com")
    [p] = await portal.query("SELECT id FROM pending_share")
    await operator.action(f"/bases/{base_id}/pending-shares/{p['id']}/remove")
    assert newcomer

    operator_ip, user_ip = "203.0.113.7", "198.51.100.9"
    assert await share_audit(portal) == [
        {"kind": "share_added", "actor": OPERATOR, "base_id": base_id,
         "ip": operator_ip, "email": COLLEAGUE},
        {"kind": "pending_share_created", "actor": OPERATOR, "base_id": base_id,
         "ip": operator_ip, "email": "new@example.com"},
        {"kind": "share_added", "actor": "new@example.com", "base_id": base_id,
         "ip": user_ip, "email": "new@example.com"},
        {"kind": "share_removed", "actor": OPERATOR, "base_id": base_id,
         "ip": operator_ip, "email": "new@example.com"},
        {"kind": "share_left", "actor": COLLEAGUE, "base_id": base_id,
         "ip": user_ip, "email": COLLEAGUE},
        {"kind": "pending_share_created", "actor": OPERATOR, "base_id": base_id,
         "ip": operator_ip, "email": "later@example.com"},
        {"kind": "pending_share_removed", "actor": OPERATOR, "base_id": base_id,
         "ip": operator_ip, "email": "later@example.com"},
    ]  # fmt: skip


async def test_only_the_operator_gets_share_controls_in_the_list(
    operator: Browser, colleague: Browser, base_id: str
):
    mine = base_card((await operator.get("/")).text, base_id)
    theirs = base_card((await colleague.get("/")).text, base_id)

    assert "shared" not in mine and "shares" in mine and "leave" not in mine
    assert theirs["shared"] == ["Shared"]
    assert "shares" not in theirs and "leave" in theirs
    assert "open-remotely" in theirs


async def test_a_withdrawn_pending_share_never_converts(
    portal: Portal, operator: Browser, base_id: str, users: Users
):
    await share(operator, base_id, COLLEAGUE)
    [p] = await portal.query("SELECT id FROM pending_share")
    await operator.action(f"/bases/{base_id}/pending-shares/{p['id']}/remove")

    colleague = await users.sign_in(COLLEAGUE)

    assert base_id not in (await colleague.get("/")).text
