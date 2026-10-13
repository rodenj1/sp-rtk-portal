"""Seam 1: Shares and Pending shares (ticket #94).

The Operator Claims a base through the real agent, then Shares it by email
on the base's Shares page. Email goes through a real SMTP conversation with
the fake server (``smtp``); what users see comes from the Portal's pages.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AsyncExitStack

import pytest

from .harness.agent import RunningAgent, running_agent
from .harness.fake_authentik import FakeAuthentik
from .harness.fake_smtp import FakeSmtp
from .harness.pages import base_card, fields
from .harness.portal import Browser, Portal

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
async def agent(portal: Portal, operator: Browser) -> AsyncIterator[RunningAgent]:
    async with running_agent(portal) as a:
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
