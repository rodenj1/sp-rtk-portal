"""Sign in and sign out on the Portal's own pages (ADR 0003)."""

from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"


async def test_signed_out_visitor_is_sent_to_the_login_page(browser: Browser):
    resp = await browser.get("/")

    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
    login = await browser.get("/login")
    assert login.status_code == 200
    assert 'name="email"' in login.text and 'name="password"' in login.text


async def test_sign_in_with_email_and_password_lands_on_an_empty_base_list(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, PASSWORD)

    resp = await browser.sign_in(EMAIL, PASSWORD)

    assert resp.status_code == 200
    assert resp.json() == {"next": "/"}
    page = await browser.get("/")
    assert page.status_code == 200
    assert EMAIL in page.text
    assert "No bases yet" in page.text


async def test_wrong_password_shows_an_error_on_the_portal(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, PASSWORD)

    resp = await browser.sign_in(EMAIL, "wrong")

    assert resp.status_code == 401
    assert resp.json() == {"error": "Wrong email or password."}
    assert (await browser.get("/")).headers["location"] == "/login"


async def test_unknown_email_shows_the_same_error(browser: Browser):
    resp = await browser.sign_in("nobody@example.com", PASSWORD)

    assert resp.status_code == 401
    assert resp.json() == {"error": "Wrong email or password."}


async def test_account_with_totp_signs_in_after_the_code(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, PASSWORD, totp="246810")

    first = await browser.action("/login", {"email": EMAIL, "password": PASSWORD})
    assert first.json() == {"step": "totp"}
    assert (await browser.get("/")).status_code == 303  # not signed in yet

    resp = await browser.action("/login/totp", {"code": "246810"})

    assert resp.json() == {"next": "/"}
    assert EMAIL in (await browser.get("/")).text


async def test_wrong_totp_code_shows_an_error_and_allows_another_try(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, PASSWORD, totp="246810")
    await browser.action("/login", {"email": EMAIL, "password": PASSWORD})

    wrong = await browser.action("/login/totp", {"code": "000000"})
    assert wrong.status_code == 401
    assert wrong.json() == {"error": "Wrong code. Try again."}

    right = await browser.action("/login/totp", {"code": "246810"})
    assert right.json() == {"next": "/"}


async def test_totp_step_times_out_after_ten_minutes(
    browser: Browser, authentik: FakeAuthentik, clock
):
    authentik.add_user(EMAIL, PASSWORD, totp="246810")
    await browser.action("/login", {"email": EMAIL, "password": PASSWORD})
    clock.advance(minutes=11)

    resp = await browser.action("/login/totp", {"code": "246810"})

    assert resp.status_code == 400
    assert resp.json()["step"] == "password"


async def test_authentik_is_told_the_client_ip(portal, authentik: FakeAuthentik):
    authentik.add_user(EMAIL, PASSWORD)
    async with portal.browser(ip="198.51.100.23") as browser:
        await browser.sign_in(EMAIL, PASSWORD)

    assert authentik.executor_requests
    for headers in authentik.executor_requests:
        assert headers["cf-connecting-ip"] == "198.51.100.23"


async def test_an_unexpected_first_stage_fails_closed_without_redirect(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, PASSWORD)
    authentik.script_challenge(
        {"component": "ak-stage-consent", "header_text": "Allow access?"}
    )

    resp = await browser.sign_in(EMAIL, PASSWORD)

    _assert_failed_closed(resp)
    assert (await browser.get("/")).headers["location"] == "/login"


async def test_an_unexpected_stage_after_the_password_fails_closed(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, PASSWORD)
    authentik.script_challenge(_identification())
    authentik.script_challenge(
        {"component": "xak-flow-redirect", "to": "https://evil.example/phish"}
    )

    resp = await browser.sign_in(EMAIL, PASSWORD)

    _assert_failed_closed(resp)


async def test_an_unknown_stage_after_the_totp_code_fails_closed(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, PASSWORD, totp="246810")
    await browser.action("/login", {"email": EMAIL, "password": PASSWORD})
    authentik.script_challenge({"component": "ak-stage-prompt", "fields": []})

    resp = await browser.action("/login/totp", {"code": "246810"})

    _assert_failed_closed(resp)


def _identification() -> dict:
    return {
        "component": "ak-stage-identification",
        "user_fields": ["email"],
        "password_fields": True,
    }


def _assert_failed_closed(resp) -> None:
    assert resp.status_code == 502
    assert "location" not in resp.headers
    assert resp.json() == {"error": "Sign-in failed. Please try again later."}
    assert "__Host-portal_session" not in resp.headers.get("set-cookie", "")


async def test_email_is_re_read_from_authentik_on_every_login(
    portal, authentik: FakeAuthentik
):
    user = authentik.add_user(EMAIL, PASSWORD)
    async with portal.browser() as browser:
        await browser.sign_in(EMAIL, PASSWORD)

    authentik.users.pop(EMAIL)
    user.email = "renamed@example.com"
    authentik.users[user.email] = user
    async with portal.browser() as browser:
        await browser.sign_in("renamed@example.com", PASSWORD)
        page = await browser.get("/")

    assert "renamed@example.com" in page.text
    accounts = await portal.query("SELECT email FROM account")
    assert accounts == [{"email": "renamed@example.com"}]
