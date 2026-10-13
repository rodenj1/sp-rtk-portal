"""The account page: TOTP on and off, and password change."""

import re

import pytest

from sp_rtk_portal.accounts.events import PasswordChanged

from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser, Portal

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"
NEW = "a brand new password"


@pytest.fixture
async def signed_in(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
def password_changes(portal: Portal) -> list[PasswordChanged]:
    seen: list[PasswordChanged] = []

    async def record(conn, event: PasswordChanged) -> None:
        seen.append(event)

    portal.context.account_events.on_password_changed(record)
    return seen


async def _turn_on_totp(browser: Browser, authentik: FakeAuthentik) -> str:
    start = await browser.action("/account/totp", {"password": PASSWORD})
    assert start.json() == {"next": "/account/totp/setup"}
    page = await browser.get("/account/totp/setup")
    assert page.status_code == 200
    assert "<svg" in page.text  # the QR code, drawn server-side
    secret = re.search(r'<code class="secret">([A-Z2-7]+)</code>', page.text)
    assert secret
    code = authentik.totp_code(secret.group(1))
    done = await browser.action("/account/totp/confirm", {"code": code})
    assert done.json() == {"next": "/account"}
    return secret.group(1)


async def test_the_account_page_needs_a_session(browser: Browser):
    resp = await browser.get("/account")

    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


async def test_the_account_page_shows_the_email_and_totp_off(signed_in: Browser):
    page = await signed_in.get("/account")

    assert page.status_code == 200
    assert EMAIL in page.text
    assert "Two-step sign-in is off" in page.text
    assert 'data-action="/account/totp"' in page.text


async def test_turn_on_totp_then_sign_in_needs_the_code(
    portal: Portal, signed_in: Browser, authentik: FakeAuthentik
):
    secret = await _turn_on_totp(signed_in, authentik)

    assert "Two-step sign-in is on" in (await signed_in.get("/account")).text
    async with portal.browser() as other:
        first = await other.sign_in(EMAIL, PASSWORD)
        assert first.json() == {"step": "totp"}
        resp = await other.action("/login/totp", {"code": authentik.totp_code(secret)})
        assert resp.json() == {"next": "/"}


async def test_turning_on_totp_needs_the_password(
    signed_in: Browser, authentik: FakeAuthentik
):
    resp = await signed_in.action("/account/totp", {"password": "wrong"})

    assert resp.status_code == 401
    assert resp.json() == {"error": "Wrong password."}
    assert not authentik.users[EMAIL].has_totp


async def test_a_wrong_confirmation_code_can_be_retried(
    signed_in: Browser, authentik: FakeAuthentik
):
    await signed_in.action("/account/totp", {"password": PASSWORD})
    page = await signed_in.get("/account/totp/setup")
    secret = re.search(r'<code class="secret">([A-Z2-7]+)</code>', page.text).group(1)

    wrong = await signed_in.action("/account/totp/confirm", {"code": "000000"})
    assert wrong.status_code == 401
    assert not authentik.users[EMAIL].has_totp

    right = await signed_in.action(
        "/account/totp/confirm", {"code": authentik.totp_code(secret)}
    )
    assert right.json() == {"next": "/account"}
    assert authentik.users[EMAIL].has_totp


async def test_the_setup_page_belongs_to_whoever_started_it(
    portal: Portal, signed_in: Browser, authentik: FakeAuthentik
):
    await signed_in.action("/account/totp", {"password": PASSWORD})
    authentik.add_user("other@example.com", PASSWORD)
    async with portal.browser() as other:
        await other.sign_in("other@example.com", PASSWORD)
        other.cookies.set(
            "__Host-portal_flow",
            signed_in.cookies.get("__Host-portal_flow"),
            domain="sp-rtk-base.big-spray.com",
        )
        page = await other.get("/account/totp/setup")

    assert page.status_code == 303
    assert page.headers["location"] == "/account"


async def test_turn_totp_off_with_password_and_code(
    portal: Portal, signed_in: Browser, authentik: FakeAuthentik
):
    secret = await _turn_on_totp(signed_in, authentik)

    wrong = await signed_in.action(
        "/account/totp/disable", {"password": PASSWORD, "code": "000000"}
    )
    assert wrong.status_code == 401
    assert authentik.users[EMAIL].has_totp

    resp = await signed_in.action(
        "/account/totp/disable",
        {"password": PASSWORD, "code": authentik.totp_code(secret)},
    )

    assert resp.json() == {"next": "/account"}
    assert "Two-step sign-in is off" in (await signed_in.get("/account")).text
    async with portal.browser() as other:
        assert (await other.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    kinds = await portal.query(
        "SELECT kind FROM audit_entry WHERE kind LIKE 'totp%%' ORDER BY id"
    )
    assert [k["kind"] for k in kinds] == ["totp_enabled", "totp_disabled"]


async def test_an_unknown_stage_in_totp_setup_fails_closed(
    signed_in: Browser, authentik: FakeAuthentik
):
    authentik.script_challenge({"component": "ak-stage-authenticator-webauthn"})

    resp = await signed_in.action("/account/totp", {"password": PASSWORD})

    assert resp.status_code == 502
    assert "location" not in resp.headers
    assert (await signed_in.get("/account/totp/setup")).status_code == 303


async def test_change_password_fires_the_hook_and_keeps_this_session(
    portal: Portal, signed_in: Browser, authentik: FakeAuthentik, password_changes
):
    resp = await signed_in.action(
        "/account/password",
        {"current_password": PASSWORD, "password": NEW, "password_repeat": NEW},
    )

    assert resp.json() == {"next": "/account/review"}
    assert authentik.users[EMAIL].password == NEW
    [event] = password_changes
    assert event.how == "change"
    assert event.keep_session_token == signed_in.cookies.get("__Host-portal_session")
    kinds = await portal.query(
        "SELECT kind FROM audit_entry WHERE kind = 'password_change'"
    )
    assert len(kinds) == 1
    assert (await signed_in.get("/account")).status_code == 200


async def test_change_password_with_totp_asks_for_the_code(
    signed_in: Browser, authentik: FakeAuthentik, password_changes
):
    authentik.users[EMAIL].totp = "246810"

    first = await signed_in.action(
        "/account/password",
        {"current_password": PASSWORD, "password": NEW, "password_repeat": NEW},
    )
    assert first.json() == {"step": "totp"}
    resp = await signed_in.action("/account/password/totp", {"code": "246810"})

    assert resp.json() == {"next": "/account/review"}
    assert authentik.users[EMAIL].password == NEW
    assert len(password_changes) == 1


async def test_change_password_needs_the_current_one(
    signed_in: Browser, authentik: FakeAuthentik, password_changes
):
    resp = await signed_in.action(
        "/account/password",
        {"current_password": "wrong", "password": NEW, "password_repeat": NEW},
    )

    assert resp.status_code == 401
    assert resp.json() == {"error": "Wrong password."}
    assert authentik.users[EMAIL].password == PASSWORD
    assert password_changes == []


async def test_an_unknown_stage_in_password_change_fails_closed(
    signed_in: Browser, authentik: FakeAuthentik, password_changes
):
    authentik.script_challenge(
        {"component": "ak-stage-identification", "password_fields": True}
    )
    authentik.script_challenge({"component": "ak-stage-user-delete"})

    resp = await signed_in.action(
        "/account/password",
        {"current_password": PASSWORD, "password": NEW, "password_repeat": NEW},
    )

    assert resp.status_code == 502
    assert "location" not in resp.headers
    assert password_changes == []


# --- an account that left portal-users (Authentik's deny stage) -----------------


async def test_totp_setup_is_refused_once_the_account_leaves_portal_users(
    signed_in: Browser, authentik: FakeAuthentik
):
    authentik.users[EMAIL].groups = ["admins"]

    resp = await signed_in.action("/account/totp", {"password": PASSWORD})

    # As for a wrong password: Authentik's own deny message never shows.
    assert resp.status_code == 401
    assert resp.json() == {"error": "Wrong password."}
    assert not authentik.users[EMAIL].has_totp


async def test_password_change_is_refused_once_the_account_leaves_portal_users(
    signed_in: Browser, authentik: FakeAuthentik, password_changes
):
    authentik.users[EMAIL].groups = ["admins"]

    resp = await signed_in.action(
        "/account/password",
        {"current_password": PASSWORD, "password": NEW, "password_repeat": NEW},
    )

    assert resp.status_code == 401
    assert resp.json() == {"error": "Wrong password."}
    assert authentik.users[EMAIL].password == PASSWORD
    assert password_changes == []
