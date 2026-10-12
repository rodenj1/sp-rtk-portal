"""The Portal session: a __Host- cookie, 30 days, renewed on use."""

from http.cookies import SimpleCookie

import pytest

from .harness.clock import FakeClock
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"
COOKIE = "__Host-portal_session"


@pytest.fixture
async def signed_in(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    resp = await browser.sign_in(EMAIL, PASSWORD)
    assert resp.json() == {"next": "/"}
    return browser


def _session_cookie(resp):
    for header in resp.headers.get_list("set-cookie"):
        cookie = SimpleCookie(header)
        if COOKIE in cookie:
            return cookie[COOKIE], header
    raise AssertionError(f"no {COOKIE} cookie set")


async def test_session_cookie_is_host_prefixed_httponly_secure_lax_for_30_days(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, PASSWORD)

    resp = await browser.sign_in(EMAIL, PASSWORD)

    morsel, header = _session_cookie(resp)
    assert morsel["path"] == "/"
    assert morsel["domain"] == ""  # __Host- forbids Domain
    assert morsel["secure"] is True
    assert morsel["httponly"] is True
    assert morsel["samesite"] == "lax"
    assert morsel["max-age"] == str(30 * 24 * 3600)
    assert header.startswith(f"{COOKIE}=")


async def test_session_expires_after_30_days_of_disuse(
    signed_in: Browser, clock: FakeClock
):
    clock.advance(days=30, seconds=1)

    resp = await signed_in.get("/")

    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


async def test_using_the_session_renews_it(signed_in: Browser, clock: FakeClock):
    for _ in range(3):
        clock.advance(days=29)
        resp = await signed_in.get("/")
        assert resp.status_code == 200
        morsel, _ = _session_cookie(resp)
        assert morsel["max-age"] == str(30 * 24 * 3600)

    clock.advance(days=30, seconds=1)
    assert (await signed_in.get("/")).status_code == 303


async def test_sign_out_ends_the_portal_session(signed_in: Browser):
    token = signed_in.cookies[COOKIE]

    resp = await signed_in.action("/logout")

    assert resp.status_code == 200
    assert resp.json() == {"next": "/login"}
    morsel, _ = _session_cookie(resp)
    assert morsel.value == "" or morsel["max-age"] == "0"
    assert (await signed_in.get("/")).status_code == 303
    # The old cookie is dead server-side too, not just forgotten by the browser.
    signed_in.cookies.set(COOKIE, token, domain="sp-rtk-base.big-spray.com")
    assert (await signed_in.get("/")).status_code == 303


async def test_a_made_up_session_cookie_is_not_signed_in(browser: Browser):
    browser.cookies.set(COOKIE, "forged", domain="sp-rtk-base.big-spray.com")

    assert (await browser.get("/")).status_code == 303
