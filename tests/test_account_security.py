"""Seam 1: account security (ticket #96).

Log out everywhere (by hand, and automatically after a password change or
recovery), the review of recent Shares after one, email changes, and
account deletion.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from .harness.agent import RunningAgent, running_agent
from .harness.fake_authentik import FakeAuthentik
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
