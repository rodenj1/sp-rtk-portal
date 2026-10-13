"""Seam 1: the audit log page and its 90-day retention (ticket #99).

Every listed event is driven through the real Portal (and the real agent
for Claims and Un-claims); what users see comes from ``/audit``, read row
by row with ``pages.entries``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack

import pytest

from .harness.agent import BASE_IP, RunningAgent, running_agent
from .harness.clock import FakeClock
from .harness.fake_authentik import FakeAuthentik
from .harness.pages import entries
from .harness.portal import Browser, Portal

OPERATOR = "operator@example.com"
COLLEAGUE = "sam@example.com"
PASSWORD = "correct horse battery staple"
BASE_NAME = "North field"
OPERATOR_IP = "203.0.113.7"
COLLEAGUE_IP = "198.51.100.9"


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


@pytest.fixture
async def stack() -> AsyncIterator[AsyncExitStack]:
    async with AsyncExitStack() as s:
        yield s


async def sign_in(
    portal: Portal, stack: AsyncExitStack, email: str, ip: str = COLLEAGUE_IP
) -> Browser:
    """A new browser at ``ip`` signed in as ``email`` (made if new)."""
    if email.lower() not in portal.authentik.users:
        portal.authentik.add_user(email, PASSWORD)
    b = await stack.enter_async_context(portal.browser(ip=ip))
    assert (await b.sign_in(email, PASSWORD)).json() == {"next": "/"}
    return b


async def audit(who: Browser) -> list[dict[str, str]]:
    resp = await who.get("/audit")
    assert resp.status_code == 200, resp.text
    return entries(resp.text)


def stamp(clock: FakeClock) -> str:
    return clock.now().strftime("%Y-%m-%d %H:%M UTC")


def brief(rows: list[dict[str, str]]) -> list[tuple[str, str, str, str]]:
    """(kind, who, base, ip) per row, newest first."""
    return [(r["@data-kind"], r["who"], r["base"], r["ip"]) for r in rows]


# --- What the Operator sees ------------------------------------------------------


async def test_a_claim_shows_who_which_base_when_and_from_where(
    operator: Browser, base_id: str, portal: Portal
):
    rows = await audit(operator)

    claim = next(r for r in rows if r["@data-kind"] == "claim")
    assert claim["what"] == "Claimed the base"
    assert claim["who"] == OPERATOR
    assert claim["base"] == BASE_NAME
    assert claim["ip"] == OPERATOR_IP
    assert claim["when@datetime"]


async def test_every_listed_event_on_the_operators_bases_shows_on_their_page(
    portal: Portal,
    operator: Browser,
    agent: RunningAgent,
    base_id: str,
    stack: AsyncExitStack,
    clock: FakeClock,
):
    colleague = await sign_in(portal, stack, COLLEAGUE)
    shares = f"/bases/{base_id}/shares"
    assert (await operator.action(shares, {"email": COLLEAGUE})).status_code == 200
    assert (
        await operator.action(shares, {"email": "new@example.com"})
    ).status_code == 200
    opened = await colleague.action(f"/bases/{base_id}/remote")
    assert opened.json() == {"next": f"/bases/{base_id}"}
    assert (await colleague.action(f"/bases/{base_id}/leave")).json() == {"next": "/"}
    assert (await operator.action(shares, {"email": COLLEAGUE})).status_code == 200
    [sam] = await portal.query("SELECT id FROM account WHERE email = %s", COLLEAGUE)
    removed = await operator.action(f"{shares}/{sam['id']}/remove")
    assert removed.status_code == 200
    when = stamp(clock)
    await agent.unclaim()
    assert (await operator.action("/account/logout-everywhere")).status_code == 200
    again = await sign_in(portal, stack, OPERATOR, ip=OPERATOR_IP)

    rows = await audit(again)

    assert brief(rows) == [
        ("login", OPERATOR, "", OPERATOR_IP),
        ("log_out_everywhere", OPERATOR, "", OPERATOR_IP),
        ("unclaim", OPERATOR, BASE_NAME, BASE_IP),
        ("pending_share_removed", OPERATOR, BASE_NAME, ""),
        ("share_removed", OPERATOR, BASE_NAME, OPERATOR_IP),
        ("share_added", OPERATOR, BASE_NAME, OPERATOR_IP),
        ("remote_session_end", COLLEAGUE, BASE_NAME, COLLEAGUE_IP),
        ("share_left", COLLEAGUE, BASE_NAME, COLLEAGUE_IP),
        ("remote_session_start", COLLEAGUE, BASE_NAME, COLLEAGUE_IP),
        ("pending_share_created", OPERATOR, BASE_NAME, OPERATOR_IP),
        ("share_added", OPERATOR, BASE_NAME, OPERATOR_IP),
        ("claim", OPERATOR, BASE_NAME, OPERATOR_IP),
        ("login", OPERATOR, "", OPERATOR_IP),
    ]
    assert [r["what"] for r in rows] == [
        "Signed in",
        "Logged out everywhere",
        "Un-claimed the base (from the base itself)",
        "Withdrew the Pending share for new@example.com (base Un-claimed)",
        f"Removed {COLLEAGUE}'s Share",
        f"Shared the base with {COLLEAGUE}",
        "Remote session ended (left the Share)",
        "Left the Share",
        "Remote session started",
        "Pending share for new@example.com",
        f"Shared the base with {COLLEAGUE}",
        "Claimed the base",
        "Signed in",
    ]
    assert rows[2]["when"] == when


# --- What a Shared user sees -------------------------------------------------------


async def test_a_shared_user_sees_only_their_own_entries(
    portal: Portal,
    operator: Browser,
    base_id: str,
    stack: AsyncExitStack,
):
    third = "third@example.com"
    colleague = await sign_in(portal, stack, COLLEAGUE)
    other = await sign_in(portal, stack, third, ip="192.0.2.44")
    shares = f"/bases/{base_id}/shares"
    for email in (COLLEAGUE, third):
        assert (await operator.action(shares, {"email": email})).status_code == 200
    for who in (operator, other, colleague):
        assert (await who.action(f"/bases/{base_id}/remote")).status_code == 200
    [sam] = await portal.query("SELECT id FROM account WHERE email = %s", COLLEAGUE)
    removed = await operator.action(f"{shares}/{sam['id']}/remove")
    assert removed.status_code == 200

    page = await colleague.get("/audit")
    rows = entries(page.text)

    assert brief(rows) == [
        ("remote_session_end", COLLEAGUE, BASE_NAME, COLLEAGUE_IP),
        ("share_removed", "The Operator", BASE_NAME, ""),
        ("remote_session_start", COLLEAGUE, BASE_NAME, COLLEAGUE_IP),
        ("share_added", "The Operator", BASE_NAME, ""),
        ("login", COLLEAGUE, "", COLLEAGUE_IP),
    ]
    assert rows[0]["what"] == "Remote session ended (Share removed)"
    for leak in (OPERATOR, OPERATOR_IP, third, "192.0.2.44"):
        assert leak not in page.text


# --- Retention ----------------------------------------------------------------------


async def until_gone(portal: Portal, kind_count: int, timeout: float = 5) -> None:
    """Wait (real time) for the purge to leave ``kind_count`` entries."""
    deadline = asyncio.get_running_loop().time() + timeout
    while len(await portal.query("SELECT id FROM audit_entry")) != kind_count:
        assert asyncio.get_running_loop().time() < deadline, "not purged"
        await asyncio.sleep(0.02)


async def test_entries_older_than_90_days_are_purged(
    portal: Portal, operator: Browser, clock: FakeClock, stack: AsyncExitStack
):
    clock.advance(days=60)
    await sign_in(portal, stack, OPERATOR, ip="192.0.2.60")
    clock.advance(days=30, minutes=1)

    await until_gone(portal, 1)

    later = await sign_in(portal, stack, OPERATOR, ip="192.0.2.90")
    assert brief(await audit(later)) == [
        ("login", OPERATOR, "", "192.0.2.90"),
        ("login", OPERATOR, "", "192.0.2.60"),
    ]
    clock.advance(days=90, minutes=1)
    await until_gone(portal, 0)
