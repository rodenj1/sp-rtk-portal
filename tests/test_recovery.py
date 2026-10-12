"""Password recovery on the Portal's pages: Turnstile, an emailed link that
lands on the Portal, a new password, and the ``PasswordChanged`` hook."""

from urllib.parse import urlsplit

import pytest

from sp_rtk_portal.accounts.events import PasswordChanged

from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser, Portal

EMAIL = "operator@example.com"
OLD = "correct horse battery staple"
NEW = "a brand new password"


@pytest.fixture
def password_changes(portal: Portal) -> list[PasswordChanged]:
    seen: list[PasswordChanged] = []

    async def record(conn, event: PasswordChanged) -> None:
        seen.append(event)

    portal.context.account_events.on_password_changed(record)
    return seen


async def _request_link(browser: Browser, authentik: FakeAuthentik) -> str:
    resp = await browser.action(
        "/recover",
        {"email": EMAIL, "cf-turnstile-response": authentik.turnstile_token},
    )
    assert resp.json() == {"next": "/recover/sent"}
    [email] = authentik.outbox
    parts = urlsplit(email.link)
    assert parts.path == "/reset"
    return parts.query.removeprefix("t=")


async def test_recover_page_shows_the_form_and_turnstile(browser: Browser):
    page = await browser.get("/recover")

    assert page.status_code == 200
    assert 'name="email"' in page.text
    assert 'class="cf-turnstile"' in page.text


async def test_recovery_link_lands_on_the_portal_and_sets_a_new_password(
    portal: Portal, authentik: FakeAuthentik, password_changes
):
    user = authentik.add_user(EMAIL, OLD)
    async with portal.browser() as browser:
        token = await _request_link(browser, authentik)
        assert authentik.outbox[0].to == EMAIL
        page = await browser.get(f"/reset?t={token}")
        assert page.status_code == 200
        assert f'value="{token}"' in page.text

        resp = await browser.action(
            "/reset", {"t": token, "password": NEW, "password_repeat": NEW}
        )

        assert resp.json() == {"next": "/"}
        assert EMAIL in (await browser.get("/")).text  # signed in
    assert user.password == NEW

    async with portal.browser() as other:
        assert (await other.sign_in(EMAIL, OLD)).status_code == 401
        assert (await other.sign_in(EMAIL, NEW)).json() == {"next": "/"}

    [event] = password_changes
    assert event.how == "recovery"
    [account] = await portal.query("SELECT id FROM account")
    assert event.account_id == account["id"]
    kinds = await portal.query(
        "SELECT kind FROM audit_entry WHERE kind = 'password_recovery'"
    )
    assert kinds == [{"kind": "password_recovery"}]


async def test_recovery_of_an_account_with_totp_asks_for_the_code(
    browser: Browser, authentik: FakeAuthentik, password_changes
):
    authentik.add_user(EMAIL, OLD, totp="246810")
    token = await _request_link(browser, authentik)

    first = await browser.action(
        "/reset", {"t": token, "password": NEW, "password_repeat": NEW}
    )
    assert first.json() == {"step": "totp"}
    wrong = await browser.action("/reset/totp", {"code": "000000"})
    assert wrong.status_code == 401
    assert password_changes == []

    resp = await browser.action("/reset/totp", {"code": "246810"})

    assert resp.json() == {"next": "/"}
    assert authentik.users[EMAIL].password == NEW
    assert len(password_changes) == 1


async def test_a_refused_new_password_can_be_retried_with_the_same_link(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, OLD)
    token = await _request_link(browser, authentik)

    bad = await browser.action(
        "/reset", {"t": token, "password": "short", "password_repeat": "short"}
    )
    assert bad.status_code == 400
    assert bad.json() == {"error": "Password is too short."}

    resp = await browser.action(
        "/reset", {"t": token, "password": NEW, "password_repeat": NEW}
    )
    assert resp.json() == {"next": "/"}


async def test_an_unknown_email_looks_the_same_and_sends_nothing(
    browser: Browser, authentik: FakeAuthentik
):
    resp = await browser.action(
        "/recover",
        {
            "email": "nobody@example.com",
            "cf-turnstile-response": authentik.turnstile_token,
        },
    )

    assert resp.json() == {"next": "/recover/sent"}
    assert authentik.outbox == []


async def test_a_failed_or_missing_turnstile_blocks_recovery(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, OLD)
    for body in (
        {"email": EMAIL, "cf-turnstile-response": "wrong-answer"},
        {"email": EMAIL},
    ):
        resp = await browser.action("/recover", body)

        assert resp.status_code == 400
        assert "captcha" in resp.json()["error"].lower()
    assert authentik.outbox == []


async def test_a_recovery_link_works_once(portal: Portal, authentik: FakeAuthentik):
    authentik.add_user(EMAIL, OLD)
    async with portal.browser() as browser:
        token = await _request_link(browser, authentik)
        await browser.action(
            "/reset", {"t": token, "password": NEW, "password_repeat": NEW}
        )
    async with portal.browser() as attacker:
        again = await attacker.action(
            "/reset",
            {"t": token, "password": "attacker pw", "password_repeat": "attacker pw"},
        )

    assert again.status_code == 400
    assert "expired" in again.json()["error"]
    assert authentik.users[EMAIL].password == NEW


async def test_an_unknown_stage_in_recovery_fails_closed(
    browser: Browser, authentik: FakeAuthentik, password_changes
):
    authentik.add_user(EMAIL, OLD)
    token = await _request_link(browser, authentik)
    authentik.script_challenge({"component": "ak-stage-user-delete"})

    resp = await browser.action(
        "/reset", {"t": token, "password": NEW, "password_repeat": NEW}
    )

    assert resp.status_code == 502
    assert "location" not in resp.headers
    assert password_changes == []
    assert (await browser.get("/")).status_code == 303


async def test_a_foreign_redirect_at_the_end_of_recovery_is_not_followed(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, OLD)
    token = await _request_link(browser, authentik)
    authentik.script_challenge(
        {
            "component": "ak-stage-prompt",
            "fields": [{"field_key": "password"}, {"field_key": "password_repeat"}],
        }
    )
    authentik.script_challenge(
        {"component": "xak-flow-redirect", "to": "https://evil.example/phish"}
    )

    resp = await browser.action(
        "/reset", {"t": token, "password": NEW, "password_repeat": NEW}
    )

    # The Portal asks Authentik for its own code; it never goes to "to".
    assert resp.json() == {"next": "/"}
    assert "location" not in resp.headers
