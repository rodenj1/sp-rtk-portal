"""Seam 1: account security (ticket #96).

Log out everywhere (by hand, and automatically after a password change or
recovery), the review of recent Shares after one, email changes, and
account deletion.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

import pytest

from .harness.agent import RunningAgent, running_agent
from .harness.fake_authentik import FakeAuthentik
from .harness.pages import base_card
from .harness.portal import Browser, Portal

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"
NEW = "a brand new password"
COOKIE = "__Host-portal_session"
HOST = "sp-rtk-base.big-spray.com"


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
async def laptop(portal: Portal, operator: Browser) -> AsyncIterator[Browser]:
    """The same user signed in on a second device."""
    async with portal.browser(ip="198.51.100.20") as b:
        assert (await b.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
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


async def account_id(portal: Portal, email: str = EMAIL) -> int:
    [row] = await portal.query("SELECT id FROM account WHERE email = %s", email)
    return int(row["id"])


async def remote_session_token(portal: Portal, browser: Browser, base_id: str) -> str:
    """Open the base remotely from ``browser``; its ``/b/`` token."""
    resp = await browser.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}
    session = portal.context.tunnels.session_for(await account_id(portal), base_id)
    assert session is not None
    return str(session.token)


async def assert_token_refused(browser: Browser, base_id: str, token: str) -> None:
    resp = await browser.http.get(
        f"/b/{base_id}/s/{token}/", headers={"Sec-Fetch-Dest": "iframe"}
    )
    assert resp.status_code == 403


async def assert_signed_out(browser: Browser, token: str) -> None:
    """``token`` (a session cookie) no longer signs anyone in."""
    browser.cookies.set(COOKIE, token, domain=HOST)
    resp = await browser.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


# --- Log out everywhere ----------------------------------------------------------


async def test_log_out_everywhere_ends_every_portal_and_remote_session(
    portal: Portal, operator: Browser, laptop: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    remote = await remote_session_token(portal, laptop, base_id)
    laptop_cookie = laptop.cookies[COOKIE]
    here_cookie = operator.cookies[COOKIE]
    assert (
        'data-action="/account/logout-everywhere"'
        in (await operator.get("/account")).text
    )

    resp = await operator.action("/account/logout-everywhere")

    assert resp.json() == {"next": "/login"}
    await assert_signed_out(laptop, laptop_cookie)
    await assert_signed_out(operator, here_cookie)
    await assert_token_refused(laptop, base_id, remote)
    entries = await portal.query(
        "SELECT account_id, host(ip) AS ip, detail FROM audit_entry"
        " WHERE kind = 'log_out_everywhere'"
    )
    assert entries == [
        {
            "account_id": await account_id(portal),
            "ip": "203.0.113.7",
            "detail": {"trigger": "button"},
        }
    ]
    ends = await portal.query(
        "SELECT detail FROM audit_entry WHERE kind = 'remote_session_end'"
    )
    assert [e["detail"]["reason"] for e in ends] == ["log_out_everywhere"]


async def request_recovery_link(browser: Browser, authentik: FakeAuthentik) -> str:
    resp = await browser.action(
        "/recover",
        {"email": EMAIL, "cf-turnstile-response": authentik.turnstile_token},
    )
    assert resp.json() == {"next": "/recover/sent"}
    return authentik.outbox[-1].link.split("t=", 1)[1]


async def test_a_password_change_ends_every_other_session(
    portal: Portal, operator: Browser, laptop: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    remote = await remote_session_token(portal, laptop, base_id)
    laptop_cookie = laptop.cookies[COOKIE]

    resp = await operator.action(
        "/account/password",
        {"current_password": PASSWORD, "password": NEW, "password_repeat": NEW},
    )

    assert resp.status_code == 200, resp.text
    assert (await operator.get("/")).status_code == 200  # this one stays
    await assert_signed_out(laptop, laptop_cookie)
    await assert_token_refused(laptop, base_id, remote)
    [entry] = await portal.query(
        "SELECT account_id, detail FROM audit_entry WHERE kind = 'log_out_everywhere'"
    )
    assert entry == {
        "account_id": await account_id(portal),
        "detail": {"trigger": "password_change"},
    }


async def test_a_recovery_ends_every_session_but_the_recovering_one(
    portal: Portal,
    authentik: FakeAuthentik,
    operator: Browser,
    laptop: Browser,
    agent: RunningAgent,
):
    base_id = await base_of(agent)
    remote = await remote_session_token(portal, laptop, base_id)
    cookies = {operator: operator.cookies[COOKIE], laptop: laptop.cookies[COOKIE]}

    async with portal.browser(ip="192.0.2.50") as stranger:
        token = await request_recovery_link(stranger, authentik)
        resp = await stranger.action(
            "/reset", {"t": token, "password": NEW, "password_repeat": NEW}
        )
        assert resp.status_code == 200, resp.text
        assert (await stranger.get("/")).status_code == 200

    for browser, cookie in cookies.items():
        await assert_signed_out(browser, cookie)
    await assert_token_refused(laptop, base_id, remote)
    [entry] = await portal.query(
        "SELECT host(ip) AS ip, detail FROM audit_entry"
        " WHERE kind = 'log_out_everywhere'"
    )
    assert entry == {"ip": "192.0.2.50", "detail": {"trigger": "password_recovery"}}


# --- Review of recent Shares after a password change or recovery ------------------

COLLEAGUE = "sam@example.com"
OLD_COLLEAGUE = "kim@example.com"
STRANGER = "nobody-yet@example.com"


async def signed_in_user(portal: Portal, email: str) -> None:
    """``email`` has a verified Portal account (signed in once)."""
    portal.authentik.add_user(email, PASSWORD)
    async with portal.browser(ip="198.51.100.9") as b:
        assert (await b.sign_in(email, PASSWORD)).json() == {"next": "/"}


def actions(html: str, prefix: str) -> list[str]:
    return re.findall(rf'data-action="({re.escape(prefix)}[^"]*)"', html)


async def test_after_a_recovery_the_review_lists_recent_shares_with_one_click_remove(
    portal: Portal, authentik: FakeAuthentik, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    for email in (OLD_COLLEAGUE, COLLEAGUE):
        await signed_in_user(portal, email)
    old = await operator.action(f"/bases/{base_id}/shares", {"email": OLD_COLLEAGUE})
    assert old.status_code == 200, old.text
    portal.clock.advance(days=31)
    assert (await operator.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    for email in (COLLEAGUE, STRANGER):
        resp = await operator.action(f"/bases/{base_id}/shares", {"email": email})
        assert resp.status_code == 200, resp.text

    async with portal.browser(ip="192.0.2.50") as me:
        token = await request_recovery_link(me, authentik)
        resp = await me.action(
            "/reset", {"t": token, "password": NEW, "password_repeat": NEW}
        )
        assert resp.json() == {"next": "/account/review"}

        page = (await me.get("/account/review")).text
        assert COLLEAGUE in page
        assert STRANGER in page
        assert OLD_COLLEAGUE not in page  # older than 30 days
        [remove_share] = actions(page, "/account/review/shares/")
        [remove_pending] = actions(page, "/account/review/pending-shares/")

        assert (await me.action(remove_share)).json() == {"next": "/account/review"}
        assert (await me.action(remove_pending)).json() == {"next": "/account/review"}

        page = (await me.get("/account/review")).text
        assert COLLEAGUE not in page
        assert STRANGER not in page
    shared = await portal.query(
        "SELECT a.email FROM share s JOIN account a ON a.id = s.account_id"
    )
    assert shared == [{"email": OLD_COLLEAGUE}]
    assert await portal.query("SELECT id FROM pending_share") == []
    kinds = await portal.query(
        "SELECT kind FROM audit_entry WHERE kind IN"
        " ('share_removed', 'pending_share_removed') ORDER BY id"
    )
    assert [k["kind"] for k in kinds] == ["share_removed", "pending_share_removed"]


async def test_the_review_can_be_skipped_and_returns_at_each_login_until_seen(
    portal: Portal, operator: Browser
):
    resp = await operator.action(
        "/account/password",
        {"current_password": PASSWORD, "password": NEW, "password_repeat": NEW},
    )
    assert resp.json() == {"next": "/account/review"}
    page = (await operator.get("/account/review")).text
    assert 'href="/"' in page and "Skip for now" in page
    assert (await operator.get("/")).status_code == 200  # skipped

    async with portal.browser() as again:
        assert (await again.sign_in(EMAIL, NEW)).json() == {"next": "/account/review"}
        assert (
            'data-action="/account/review/done"'
            in (await again.get("/account/review")).text
        )
        assert (await again.action("/account/review/done")).json() == {"next": "/"}

    async with portal.browser() as later:
        assert (await later.sign_in(EMAIL, NEW)).json() == {"next": "/"}


# --- Email change -------------------------------------------------------------------


async def test_an_email_changed_in_authentik_shows_at_next_login_and_keeps_bases_and_shares(
    portal: Portal, authentik: FakeAuthentik, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    await signed_in_user(portal, COLLEAGUE)
    resp = await operator.action(f"/bases/{base_id}/shares", {"email": COLLEAGUE})
    assert resp.status_code == 200, resp.text

    authentik.change_email(authentik.users[EMAIL], "operator@new.example")
    authentik.change_email(authentik.users[COLLEAGUE], "sam@new.example")

    async with portal.browser() as b:
        assert (await b.sign_in("operator@new.example", PASSWORD)).json() == {
            "next": "/"
        }
        assert "operator@new.example" in (await b.get("/account")).text
        assert base_card((await b.get("/")).text, base_id)
        shares = (await b.get(f"/bases/{base_id}/shares")).text
        assert "sam@example.com" in shares  # until Sam signs in again
    async with portal.browser() as b:
        assert (await b.sign_in("sam@new.example", PASSWORD)).json() == {"next": "/"}
        assert base_card((await b.get("/")).text, base_id)
    async with portal.browser() as b:
        assert (await b.sign_in("operator@new.example", PASSWORD)).status_code == 200
        shares = (await b.get(f"/bases/{base_id}/shares")).text
        assert "sam@new.example" in shares
    assert len(await portal.query("SELECT id FROM account")) == 2


# --- Account deletion ---------------------------------------------------------------


async def test_account_deletion_previews_the_bases_it_will_un_claim(
    operator: Browser, agent: RunningAgent
):
    assert 'href="/account/delete"' in (await operator.get("/account")).text

    page = (await operator.get("/account/delete")).text

    assert "North field" in page
    assert 'data-action="/account/delete"' in page


async def test_deleting_the_account_un_claims_removes_shares_ends_sessions_and_deactivates(
    portal: Portal, authentik: FakeAuthentik, operator: Browser, agent: RunningAgent
):
    base_id = await base_of(agent)
    thumbprint = agent.key.thumbprint
    me = await account_id(portal)
    await signed_in_user(portal, COLLEAGUE)
    resp = await operator.action(f"/bases/{base_id}/shares", {"email": COLLEAGUE})
    assert resp.status_code == 200, resp.text
    # Sam's own base, Shared with me, which I have open remotely.
    async with (
        portal.browser(ip="198.51.100.9") as sam,
        running_agent(portal, ip="198.51.100.10") as sams_agent,
    ):
        assert (await sam.sign_in(COLLEAGUE, PASSWORD)).json() == {"next": "/"}
        await sams_agent.claim(sam, "South field")
        sams_base = await base_of(sams_agent)
        resp = await sam.action(f"/bases/{sams_base}/shares", {"email": EMAIL})
        assert resp.status_code == 200, resp.text
        remote = await remote_session_token(portal, operator, sams_base)
        cookie = operator.cookies[COOKIE]

        resp = await operator.action("/account/delete")

        assert resp.json() == {"next": "/login"}
        # My base is Un-claimed: its agent gets 401 unclaimed and goes idle.
        status = await agent.until("not_connected")
        assert status.message and "Un-claimed on the Portal" in status.message
        assert [r["id"] for r in await portal.query("SELECT id FROM base")] == [
            sams_base
        ]
        # Every Share involving me is gone, and so is my access to Sam's base.
        assert await portal.query("SELECT base_id FROM share") == []
        assert not base_card((await sam.get("/")).text, base_id)
        await assert_token_refused(operator, sams_base, remote)
        assert (await sams_agent.status()).state == "connected"
    await assert_signed_out(operator, cookie)
    assert authentik.users[EMAIL].is_active is False
    assert ("PATCH", f"/api/v3/core/users/{authentik.users[EMAIL].pk}/") in (
        authentik.api_calls
    )
    async with portal.browser() as again:
        assert (await again.sign_in(EMAIL, PASSWORD)).status_code == 401

    entries = await portal.query(
        "SELECT kind, account_id, base_id, detail FROM audit_entry"
        " WHERE kind IN ('unclaim', 'share_left', 'account_deleted') ORDER BY id"
    )
    assert entries == [
        {
            "kind": "unclaim",
            "account_id": me,
            "base_id": base_id,
            "detail": {
                "by": "account_deleted",
                "name": "North field",
                "key_thumbprint": thumbprint,
            },
        },
        {
            "kind": "share_left",
            "account_id": me,
            "base_id": sams_base,
            "detail": {
                "shared_user": me,
                "email": EMAIL,
                "reason": "account_deleted",
            },
        },
        {
            "kind": "account_deleted",
            "account_id": me,
            "base_id": None,
            "detail": {"email": EMAIL, "unclaimed": [base_id]},
        },
    ]
    ends = await portal.query(
        "SELECT detail FROM audit_entry WHERE kind = 'remote_session_end'"
    )
    assert [e["detail"]["reason"] for e in ends] == ["account_deleted"]


async def test_account_deletion_changes_nothing_if_authentik_refuses(
    portal: Portal, authentik: FakeAuthentik, operator: Browser, agent: RunningAgent
):
    authentik.api_token = "revoked"

    resp = await operator.action("/account/delete")

    assert resp.status_code == 502
    assert "error" in resp.json()
    assert len(await portal.query("SELECT id FROM base")) == 1
    assert (await operator.get("/")).status_code == 200
    assert authentik.users[EMAIL].is_active is True
